package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func TestNativeProtocolsRewriteAliasAndIsolateUpstreamCredentials(t *testing.T) {
	type received struct {
		path, method string
		header       http.Header
		body         map[string]json.RawMessage
	}
	requests := make(chan received, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid test input", 400)
			return
		}
		requests <- received{r.URL.Path, r.Method, r.Header.Clone(), body}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"model":"native-model","metadata":{"model":"native-model"},"usage":{"input_tokens":5,"output_tokens":3},"data":[]}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL+"/v1", "upstream-only-secret")
	clientKey := f.key(t, "client", "llmgw_client-private-token")
	m := f.model(t, e, "public-alias", []string{}, []string{clientKey.ID})
	cases := []struct {
		endpoint string
		body     map[string]any
	}{
		{"/v1/chat/completions", chatBody(m.Alias)},
		{"/v1/responses", map[string]any{"model": m.Alias, "input": "Hello", "instructions": "Be concise"}},
		{"/v1/completions", map[string]any{"model": m.Alias, "prompt": "Hello"}},
		{"/v1/embeddings", map[string]any{"model": m.Alias, "input": []string{"Hello"}}},
		{"/v1/rerank", map[string]any{"model": m.Alias, "query": "Hello", "documents": []string{"World"}}},
		{"/v1/messages", map[string]any{"model": m.Alias, "messages": []any{map[string]any{"role": "user", "content": "Hello"}}, "max_tokens": 20}},
	}
	for _, test := range cases {
		t.Run(test.endpoint, func(t *testing.T) {
			test.body["extension"] = json.RawMessage(`{"big":9007199254740993,"nested":{"model":"leave-intact"}}`)
			r := requestJSON(t, "POST", test.endpoint, test.body)
			r.Header.Set("Authorization", "Bearer llmgw_client-private-token")
			r.Header.Set("X-Api-Key", "untrusted-key")
			r.Header.Set("Cookie", "llmgw_session=private-browser-session")
			w := serve(t, f.server, r, 200)
			result := decodeResponse[map[string]json.RawMessage](t, w)
			if string(result["model"]) != `"public-alias"` || string(result["metadata"]) != `{"model":"native-model"}` {
				t.Fatalf("response model normalization=%s", w.Body.String())
			}
			got := <-requests
			if got.path != test.endpoint || got.method != "POST" || string(got.body["model"]) != `"native-model"` {
				t.Fatalf("wrong native route: %+v", got)
			}
			if got.header.Get("Authorization") != "Bearer upstream-only-secret" || got.header.Get("X-Api-Key") != "" || got.header.Get("Cookie") != "" {
				t.Fatalf("credentials not isolated: %v", got.header)
			}
			if string(got.body["extension"]) != `{"big":9007199254740993,"nested":{"model":"leave-intact"}}` {
				t.Fatalf("lost extension: %s", got.body["extension"])
			}
			for field, value := range test.body {
				if field == "model" {
					continue
				}
				want, err := json.Marshal(value)
				if err != nil || string(got.body[field]) != string(want) {
					t.Fatalf("native %s field changed: got=%s want=%s err=%v", field, got.body[field], want, err)
				}
			}
			if test.endpoint == "/v1/messages" && got.header.Get("Anthropic-Version") == "" {
				t.Fatal("native messages version header missing")
			}
		})
	}
	records := f.accessRecords(t)
	if len(records) != 6 {
		t.Fatalf("logged %d requests", len(records))
	}
	for _, record := range records {
		if record.APIKeyID != clientKey.ID || record.ModelAlias != m.Alias || record.UpstreamModel != "native-model" || record.InputTokens != 5 || record.OutputTokens != 3 || record.TotalTokens != 8 {
			t.Fatalf("incorrect snapshot: %+v", record)
		}
	}
	storedKey, err := f.store.GetAPIKey(context.Background(), clientKey.ID)
	if err != nil || storedKey.LastUsedAt == "" {
		t.Fatalf("key use not tracked: %+v err=%v", storedKey, err)
	}
}

func TestModelListingUsesTCPPeerAndBothACLs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"model":"native-model"}`) }))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	k := f.key(t, "allowed", "llmgw_allowed")
	f.model(t, e, "public", []string{}, []string{})
	f.model(t, e, "local", nil, []string{})
	f.model(t, e, "key", []string{}, []string{k.ID})
	f.model(t, e, "both", []string{"10.0.0.0/8"}, []string{k.ID})
	hidden := f.model(t, e, "hidden", []string{}, []string{})
	hidden.Published = false
	if err := f.store.SaveModel(context.Background(), &hidden); err != nil {
		t.Fatal(err)
	}
	disabled := f.engine(t, upstream.URL, "")
	f.model(t, disabled, "disabled", []string{}, []string{})
	disabled.Enabled = false
	if err := f.store.SaveEngine(context.Background(), &disabled); err != nil {
		t.Fatal(err)
	}
	gone := f.engine(t, upstream.URL, "")
	f.model(t, gone, "unavailable", []string{}, []string{})
	if err := f.store.SyncModels(context.Background(), gone.ID, nil); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, bearer string
		want                 []string
	}{
		{"anonymous remote", "203.0.113.8:54321", "", []string{"public"}},
		{"unknown bearer unrestricted", "203.0.113.8:54321", "unknown", []string{"public"}},
		{"loopback defaults", "127.0.0.1:54321", "", []string{"local", "public"}},
		{"mapped IPv4 defaults", "[::ffff:127.0.0.1]:54321", "", []string{"local", "public"}},
		{"key without matching IP", "203.0.113.8:54321", "llmgw_allowed", []string{"key", "public"}},
		{"AND both match", "10.2.3.4:54321", "llmgw_allowed", []string{"both", "key", "public"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r := requestJSON(t, "GET", "/v1/models", nil)
			r.RemoteAddr = test.remote
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			r.Header.Set("X-Real-IP", "127.0.0.1")
			r.Header.Set("Forwarded", "for=127.0.0.1")
			if test.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			w := serve(t, f.server, r, 200)
			var result struct {
				Object string `json:"object"`
				Data   []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, model := range result.Data {
				got = append(got, model.ID)
			}
			slices.Sort(got)
			if result.Object != "list" || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("models=%v want=%v body=%s", got, test.want, w.Body.String())
			}
		})
	}
}

func TestGenerationACLsAndDisabledKeys(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"model":"native-model"}`) }))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	allowed := f.key(t, "allowed", "llmgw_allowed")
	f.key(t, "other", "llmgw_other")
	f.model(t, e, "unrestricted", []string{}, []string{})
	f.model(t, e, "restricted", []string{"10.0.0.0/8"}, []string{allowed.ID})
	f.model(t, e, "key-only", []string{}, []string{allowed.ID})
	cases := []struct {
		name, alias, remote, bearer string
		status                      int
		code                        string
	}{
		{"unknown bearer ignored", "unrestricted", "203.0.113.8:1234", "unknown", 200, ""},
		{"IP alone insufficient", "restricted", "10.1.2.3:1234", "", 401, "unauthorized"},
		{"unknown key", "restricted", "10.1.2.3:1234", "unknown", 401, "unauthorized"},
		{"valid unlisted key", "restricted", "10.1.2.3:1234", "llmgw_other", 403, "forbidden"},
		{"key alone insufficient", "restricted", "203.0.113.8:1234", "llmgw_allowed", 403, "forbidden"},
		{"both match", "restricted", "10.1.2.3:1234", "llmgw_allowed", 200, ""},
		{"key only", "key-only", "203.0.113.8:1234", "llmgw_allowed", 200, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r := requestJSON(t, "POST", "/v1/chat/completions", chatBody(test.alias))
			r.RemoteAddr = test.remote
			r.Header.Set("X-Forwarded-For", "10.1.2.3")
			if test.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			w := serve(t, f.server, r, test.status)
			if test.code != "" {
				assertErrorCode(t, w, test.code)
			}
		})
	}
	allowed.Enabled = false
	if err := f.store.SaveAPIKey(context.Background(), &allowed); err != nil {
		t.Fatal(err)
	}
	r := requestJSON(t, "POST", "/v1/chat/completions", chatBody("key-only"))
	r.Header.Set("Authorization", "Bearer llmgw_allowed")
	assertErrorCode(t, serve(t, f.server, r, 401), "unauthorized")
	if calls.Load() != 3 {
		t.Fatalf("rejected requests reached upstream: calls=%d", calls.Load())
	}
}

func TestGatewayAvailabilityAndCapabilitiesGateBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"model":"native-model"}`) }))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	m := f.model(t, e, "visible", []string{}, []string{})
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody("missing")), 404), "model_not_found")
	m.Published = false
	if err := f.store.SaveModel(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody(m.Alias)), 404), "model_not_found")
	m.Published = true
	m.Capabilities["responses"] = false
	m.Capabilities["streaming"] = false
	m.Capabilities["tools"] = false
	m.Capabilities["vision"] = false
	if err := f.store.SaveModel(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/responses", map[string]any{"model": m.Alias, "input": "Hello"}), 501), "unsupported_endpoint")
	for _, feature := range []string{"stream", "tools", "vision"} {
		body := chatBody(m.Alias)
		switch feature {
		case "stream":
			body["stream"] = true
		case "tools":
			body["tools"] = []any{map[string]any{"type": "function", "function": map[string]any{"name": "test"}}}
		case "vision":
			body["messages"] = []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,eA=="}}}}}
		}
		assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", body), 400), "unsupported_capability")
	}
	if err := f.store.SyncModels(context.Background(), e.ID, nil); err != nil {
		t.Fatal(err)
	}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody(m.Alias)), 503), "model_unavailable")
	if err := f.store.SyncModels(context.Background(), e.ID, []domain.UpstreamModel{{UpstreamID: "native-model", Capabilities: allCapabilities()}}); err != nil {
		t.Fatal(err)
	}
	e.Enabled = false
	if err := f.store.SaveEngine(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody(m.Alias)), 503), "engine_unavailable")
	if calls.Load() != 0 {
		t.Fatalf("denied request reached upstream: %d", calls.Load())
	}
	e.Enabled = true
	e.Status = "Offline"
	if err := f.store.SaveEngine(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody(m.Alias)), 200)
	if calls.Load() != 1 {
		t.Fatal("cached Offline status prevented the actual request")
	}
}

func TestMalformedInputAndUpstreamFailuresAreControlled(t *testing.T) {
	var calls atomic.Int64
	var mode atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		switch mode.Load() {
		case 0:
			http.Error(w, "private engine secret traceback", 500)
		case 1:
			http.Error(w, "private native route missing", 404)
		case 2:
			fmt.Fprint(w, `{"model":`)
		case 3:
			fmt.Fprint(w, `{"error":{"message":"private engine failure"}}`)
		case 4:
			<-r.Context().Done()
		}
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "public", []string{}, []string{})
	for _, malformed := range []string{`{`, `{"model":"public","messages":"bad"}`, `{"model":"public","messages":[]}`, `{"model":"public","messages":[{"role":"user","content":"hi"}]} {}`} {
		r := httptest.NewRequest("POST", "http://localhost:8080/v1/chat/completions", strings.NewReader(malformed))
		r.RemoteAddr = "127.0.0.1:1234"
		assertErrorCode(t, serve(t, f.server, r, 400), "invalid_request")
	}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/not-supported", nil), 501), "unsupported_endpoint")
	if calls.Load() != 0 {
		t.Fatal("malformed requests reached upstream")
	}
	for _, test := range []struct {
		mode int32
		want int
		code string
	}{{0, 502, "upstream_error"}, {1, 501, "unsupported_endpoint"}, {2, 502, "upstream_error"}, {3, 502, "upstream_error"}} {
		mode.Store(test.mode)
		w := serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody("public")), test.want)
		assertErrorCode(t, w, test.code)
		if strings.Contains(w.Body.String(), "private") {
			t.Fatalf("upstream error leaked: %s", w.Body.String())
		}
	}
	settings := domain.DefaultSettings()
	settings.RequestTimeoutSeconds = 1
	if err := f.store.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	mode.Store(4)
	started := time.Now()
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody("public")), 504), "timeout")
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("configured timeout was not applied: %v", elapsed)
	}
	upstream.Close()
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody("public")), 503), "engine_unavailable")
}

func TestHealthSyncPreservesPolicyAndRecoversReturningModels(t *testing.T) {
	var mode atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.Error(w, "wrong endpoint", 404)
			return
		}
		switch mode.Load() {
		case 0:
			io.WriteString(w, `{"data":[{"id":"native-model","capabilities":{"chat_completions":true}}]}`)
		case 1:
			http.Error(w, "probe failure", 500)
		case 2:
			io.WriteString(w, `{"data":[]}`)
		case 3:
			io.WriteString(w, `{"data":[{"id":"native-model"},{"id":"new-discovery"}]}`)
		}
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	m := f.model(t, e, "stable-alias", []string{"10.0.0.0/8"}, []string{})
	m.Capabilities["vision"] = false
	if err := f.store.SaveModel(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode      int32
		status    string
		available bool
	}{{0, "Online", true}, {1, "Degraded", true}, {2, "Online", false}, {3, "Online", true}} {
		mode.Store(test.mode)
		gotEngine, err := f.server.CheckEngine(context.Background(), e.ID)
		if err != nil || gotEngine.Status != test.status {
			t.Fatalf("probe %d engine=%+v err=%v", test.mode, gotEngine, err)
		}
		gotModel, err := f.store.GetModel(context.Background(), m.ID)
		if err != nil || gotModel.Available != test.available || gotModel.Alias != m.Alias || !gotModel.Published || !reflect.DeepEqual(gotModel.AllowedIPs, []string{"10.0.0.0/8"}) || gotModel.Capabilities["vision"] {
			t.Fatalf("probe %d policy=%+v err=%v", test.mode, gotModel, err)
		}
	}
	models, err := f.store.ListModels(context.Background())
	if err != nil || len(models) != 1 {
		t.Fatalf("discovery auto-published a model: %+v %v", models, err)
	}
}
