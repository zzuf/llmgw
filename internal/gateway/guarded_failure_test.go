package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"llmgw/internal/domain"
)

func TestGuardFailuresAreClosedAndPoliciesHotReload(t *testing.T) {
	var mode atomic.Value
	mode.Store("safe")
	var inferenceCalls atomic.Int64
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch mode.Load().(string) {
		case "unavailable":
			http.Error(w, "private upstream diagnostic", 500)
		case "invalid":
			io.WriteString(w, `{"choices":[{"message":{"content":"Safety: Unknown\nCategories: None"},"finish_reason":"stop"}]}`)
		case "timeout":
			<-r.Context().Done()
		default:
			guardReply(w, "Safe", false)
		}
	}))
	defer guard.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inferenceCalls.Add(1)
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	en := f.engine(t, guard.URL, "")
	g := createGuard(t, f, a, en)
	f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{})
	k := f.key(t, "guarded", "llmgw_failure-test")
	serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": k.Name, "enabled": true, "input_safeguard_id": g.ID}), 200)
	settings, err := f.store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.GuardTimeoutSeconds = 1
	if err = f.store.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	call := func(body any, status int, code string) {
		r := requestJSON(t, "POST", "/v1/chat/completions", body)
		r.Header.Set("Authorization", "Bearer llmgw_failure-test")
		w := serve(t, f.server, r, status)
		if code != "" {
			assertErrorCode(t, w, code)
		}
		if strings.Contains(w.Body.String(), "private upstream") {
			t.Fatal("upstream diagnostic leaked")
		}
	}
	for _, test := range []struct {
		mode   string
		status int
		code   string
	}{{"unavailable", 503, "guard_unavailable"}, {"invalid", 503, "guard_unavailable"}, {"timeout", 504, "guard_timeout"}} {
		t.Run(test.mode, func(t *testing.T) { mode.Store(test.mode); call(chatBody("chat"), test.status, test.code) })
	}
	mode.Store("safe")
	call(map[string]any{"model": "chat", "messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]string{"url": "data:image/png;base64,eA=="}}}}}}, 400, "unsupported_guard_content")
	call(map[string]any{"model": "chat", "messages": []any{map[string]any{"role": "user", "content": strings.Repeat("a", int(settings.GuardMaxTextBytes))}}}, 503, "guard_limit_exceeded")
	if inferenceCalls.Load() != 0 {
		t.Fatal("failed guard reached inference")
	}
	if err = f.store.SyncModels(context.Background(), en.ID, nil); err != nil {
		t.Fatal(err)
	}
	call(chatBody("chat"), 503, "guard_unavailable")
	if err = f.store.SyncModels(context.Background(), en.ID, []domain.UpstreamModel{{UpstreamID: "native-model", Capabilities: allCapabilities()}}); err != nil {
		t.Fatal(err)
	}
	call(chatBody("chat"), 200, "")
	g.Enabled = false
	serve(t, f.server, a.request(t, "PUT", "/admin/api/safeguards/"+g.ID, g), 200)
	call(chatBody("chat"), 503, "guard_unavailable")
	if inferenceCalls.Load() != 1 {
		t.Fatal("disabled guard reached inference")
	}
	g.Enabled = true
	serve(t, f.server, a.request(t, "PUT", "/admin/api/safeguards/"+g.ID, g), 200)
	call(chatBody("chat"), 200, "")
	if inferenceCalls.Load() != 2 {
		t.Fatal("re-enabled guard did not recover")
	}
}

func TestOutputGuardInspectsReturnedRerankDocumentsButNotNumericVectors(t *testing.T) {
	var guardCalls atomic.Int64
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { guardCalls.Add(1); guardReply(w, "Unsafe", true) }))
	defer guard.Close()
	var response atomic.Value
	response.Store(`{"model":"native-model","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}]}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, response.Load().(string))
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	g := createGuard(t, f, a, f.engine(t, guard.URL, ""))
	f.model(t, f.engine(t, upstream.URL, ""), "test", []string{}, []string{})
	k := f.key(t, "output", "llmgw_vector-key")
	serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": k.Name, "enabled": true, "output_safeguard_id": g.ID}), 200)
	call := func(path string, body any, status int) {
		r := requestJSON(t, "POST", path, body)
		r.Header.Set("Authorization", "Bearer llmgw_vector-key")
		serve(t, f.server, r, status)
	}
	call("/v1/embeddings", map[string]any{"model": "test", "input": "hello"}, 200)
	response.Store(`{"results":[{"index":0,"relevance_score":0.5}]}`)
	call("/v1/rerank", map[string]any{"model": "test", "query": "hello", "documents": []string{"document"}}, 200)
	if guardCalls.Load() != 0 {
		t.Fatal("numeric outputs called guard")
	}
	response.Store(`{"results":[{"index":0,"relevance_score":0.5,"document":{"text":"must be inspected"}}]}`)
	call("/v1/rerank", map[string]any{"model": "test", "query": "hello", "documents": []string{"document"}}, 403)
	if guardCalls.Load() != 1 {
		t.Fatal("returned document was not guarded")
	}
}
