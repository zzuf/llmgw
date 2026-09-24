package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func guardReply(w http.ResponseWriter, label string, output bool) {
	content := "Safety: " + label + "\nCategories: None"
	if label != "Safe" {
		content = "Safety: " + label + "\nCategories: Violent"
	}
	if output {
		content += "\nRefusal: No"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}})
}

func TestGuardedNativeTextProtocols(t *testing.T) {
	for _, tc := range []struct {
		endpoint, input, output string
	}{
		{"chat/completions", `"messages":[{"role":"system","content":"instruction-context"},{"role":"user","content":"question-context"}]`, `"choices":[{"index":0,"message":{"role":"assistant","content":"first-output"},"finish_reason":"stop"},{"index":1,"message":{"role":"assistant","content":"second-output"},"finish_reason":"stop"}]`},
		{"responses", `"instructions":"instruction-context","input":"question-context"`, `"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"first-output"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"second-output"}]}]`},
		{"completions", `"prompt":["instruction-context","question-context"]`, `"choices":[{"index":0,"text":"first-output","finish_reason":"stop"},{"index":1,"text":"second-output","finish_reason":"stop"}]`},
		{"messages", `"system":"instruction-context","messages":[{"role":"user","content":"question-context"}],"max_tokens":32`, `"type":"message","role":"assistant","content":[{"type":"text","text":"first-output"},{"type":"thinking","thinking":"second-output"}],"stop_reason":"end_turn"`},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			var calls atomic.Int64
			guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var body struct {
					Messages []struct{ Role, Content string }
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if len(body.Messages) < 1 {
					t.Error("missing guard context")
					return
				}
				for _, want := range []string{"instruction-context", "question-context"} {
					if !strings.Contains(body.Messages[0].Content, want) {
						t.Errorf("input context missing %s", want)
					}
				}
				output := len(body.Messages) == 2
				if output {
					for _, want := range []string{"first-output", "second-output"} {
						if !strings.Contains(body.Messages[1].Content, want) {
							t.Errorf("output projection missing %s", want)
						}
					}
				}
				guardReply(w, "Safe", output)
			}))
			defer guard.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/"+tc.endpoint {
					t.Errorf("unexpected route %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"model":"native-model",`+tc.output+`}`)
			}))
			defer upstream.Close()
			f := newGatewayFixture(t)
			a := signIn(t, f, true, "owner", administratorPassword, nil)
			g := createGuard(t, f, a, f.engine(t, guard.URL, ""))
			k := f.key(t, "protected", "llmgw_native-protocols")
			k.InputSafeguardID, k.OutputSafeguardID = &g.ID, &g.ID
			if err := f.store.SaveAPIKey(context.Background(), &k); err != nil {
				t.Fatal(err)
			}
			f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{k.ID})
			r := requestJSON(t, "POST", "/v1/"+tc.endpoint, json.RawMessage(`{"model":"chat",`+tc.input+`}`))
			r.Header.Set("Authorization", "Bearer llmgw_native-protocols")
			w := serve(t, f.server, r, 200)
			if calls.Load() != 2 || !strings.Contains(w.Body.String(), `"model":"chat"`) || !strings.Contains(w.Body.String(), "second-output") {
				t.Fatalf("unexpected guarded response, calls=%d: %s", calls.Load(), w.Body.String())
			}
		})
	}
}

func TestInFlightGuardPolicyUsesRequestSnapshot(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { guardReply(w, "Safe", true) }))
	defer guard.Close()
	started, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, `{"model":"native-model","choices":[{"message":{"role":"assistant","content":"finished"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	g := createGuard(t, f, a, f.engine(t, guard.URL, ""))
	k := f.key(t, "protected", "llmgw_policy-snapshot")
	k.OutputSafeguardID = &g.ID
	if err := f.store.SaveAPIKey(context.Background(), &k); err != nil {
		t.Fatal(err)
	}
	f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{k.ID})
	request := func() *http.Request {
		r := requestJSON(t, "POST", "/v1/chat/completions", chatBody("chat"))
		r.Header.Set("Authorization", "Bearer llmgw_policy-snapshot")
		return r
	}
	r := request()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	w, done := httptest.NewRecorder(), make(chan struct{})
	go func() { f.server.ServeHTTP(w, r.WithContext(ctx)); close(done) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("inference did not start")
	}
	g.Enabled = false
	if err := f.store.SaveSafeguard(context.Background(), &g); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("request did not complete")
	}
	if w.Code != 200 {
		t.Fatalf("in-flight policy changed: %d %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, serve(t, f.server, request(), 503), "guard_unavailable")
}

func createGuard(t *testing.T, f *gatewayFixture, a adminPrincipal, e domain.Engine) domain.Safeguard {
	t.Helper()
	w := serve(t, f.server, a.request(t, "POST", "/admin/api/safeguards", map[string]any{"name": "Safety classifier", "engine_id": e.ID, "upstream_model_id": "native-model", "adapter": "qwen3guard_gen", "enabled": true}), 201)
	return decodeResponse[domain.Safeguard](t, w)
}

func TestAdminSafeguardsAndKeyPolicyPreservation(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "Bearer guard-secret" {
			t.Error("wrong guard credential")
		}
		guardReply(w, "Safe", len(body.Messages) == 2)
	}))
	defer guard.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	en := f.engine(t, guard.URL, "guard-secret")
	serve(t, f.server, requestJSON(t, "GET", "/admin/api/safeguards", nil), 401)
	r := a.request(t, "POST", "/admin/api/safeguards", map[string]any{})
	r.Header.Del("X-CSRF-Token")
	serve(t, f.server, r, 403)
	g := createGuard(t, f, a, en)
	if g.ID == "" || !g.Available {
		t.Fatalf("guard=%+v", g)
	}
	w := serve(t, f.server, a.request(t, "POST", "/admin/api/safeguards/"+g.ID+"/check", map[string]any{}), 200)
	check := decodeResponse[struct {
		OK     bool              `json:"ok"`
		Input  domain.GuardCheck `json:"input"`
		Output domain.GuardCheck `json:"output"`
	}](t, w)
	if !check.OK || check.Input.Label != "Safe" || check.Output.Label != "Safe" {
		t.Fatalf("check=%s", w.Body.String())
	}
	w = serve(t, f.server, a.request(t, "POST", "/admin/api/keys", map[string]any{"name": "guarded", "enabled": true, "input_safeguard_id": g.ID, "output_safeguard_id": g.ID, "block_controversial": true}), 201)
	k := decodeResponse[domain.APIKey](t, w)
	if k.InputSafeguardID == nil || k.OutputSafeguardID == nil || !k.BlockControversial {
		t.Fatalf("key=%s", w.Body.String())
	}
	w = serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": "renamed", "enabled": false}), 200)
	k = decodeResponse[domain.APIKey](t, w)
	if k.InputSafeguardID == nil || *k.InputSafeguardID != g.ID || k.OutputSafeguardID == nil || !k.BlockControversial {
		t.Fatalf("policy lost on toggle=%s", w.Body.String())
	}
	serve(t, f.server, a.request(t, "DELETE", "/admin/api/safeguards/"+g.ID, nil), 409)
	serve(t, f.server, a.request(t, "DELETE", "/admin/api/engines/"+en.ID, nil), 409)
	w = serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": "renamed", "enabled": true, "input_safeguard_id": nil}), 200)
	k = decodeResponse[domain.APIKey](t, w)
	if k.InputSafeguardID != nil || k.OutputSafeguardID == nil || !k.BlockControversial {
		t.Fatalf("explicit reset=%s", w.Body.String())
	}
	serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": "renamed", "enabled": true, "output_safeguard_id": nil, "block_controversial": false}), 200)
	serve(t, f.server, a.request(t, "DELETE", "/admin/api/safeguards/"+g.ID, nil), 200)
}

func TestGuardedKeysEnforceInputOutputAndLeaveOtherKeysUnchanged(t *testing.T) {
	var guardCalls, inferenceCalls atomic.Int64
	var inputLabel, outputLabel atomic.Value
	inputLabel.Store("Safe")
	outputLabel.Store("Safe")
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardCalls.Add(1)
		var body struct {
			Model    string                           `json:"model"`
			Stream   bool                             `json:"stream"`
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "native-model" || body.Stream || r.Header.Get("Authorization") != "Bearer guard-secret" {
			t.Errorf("guard request wrong: %+v", body)
		}
		output := len(body.Messages) == 2
		label := inputLabel.Load().(string)
		if output {
			label = outputLabel.Load().(string)
		}
		guardReply(w, label, output)
	}))
	defer guard.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inferenceCalls.Add(1)
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, `{"model":"native-model","choices":[{"index":0,"message":{"role":"assistant","content":"private generated answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	g := createGuard(t, f, a, f.engine(t, guard.URL, "guard-secret"))
	f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{})
	k := f.key(t, "guarded", "llmgw_guarded-client")
	policy := func(input, output bool, controversial bool) {
		body := map[string]any{"name": k.Name, "enabled": true, "block_controversial": controversial, "input_safeguard_id": nil, "output_safeguard_id": nil}
		if input {
			body["input_safeguard_id"] = g.ID
		}
		if output {
			body["output_safeguard_id"] = g.ID
		}
		serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, body), 200)
	}
	request := func(bearer string, status int) *httptest.ResponseRecorder {
		r := requestJSON(t, "POST", "/v1/chat/completions", chatBody("chat"))
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("Origin", "https://client.example")
		w := serve(t, f.server, r, status)
		assertPublicCORS(t, w.Result().Header)
		return w
	}
	policy(true, true, false)
	request("llmgw_guarded-client", 200)
	if guardCalls.Load() != 2 || inferenceCalls.Load() != 1 {
		t.Fatal("both guards not called")
	}
	inputLabel.Store("Unsafe")
	w := request("llmgw_guarded-client", 403)
	assertErrorCode(t, w, "guard_rejected")
	if inferenceCalls.Load() != 1 {
		t.Fatal("blocked input reached inference")
	}
	inputLabel.Store("Controversial")
	request("llmgw_guarded-client", 200)
	policy(true, true, true)
	assertErrorCode(t, request("llmgw_guarded-client", 403), "guard_rejected")
	inputLabel.Store("Safe")
	outputLabel.Store("Unsafe")
	policy(false, true, false)
	w = request("llmgw_guarded-client", 403)
	if strings.Contains(w.Body.String(), "private generated answer") {
		t.Fatal("rejected output leaked")
	}
	before := guardCalls.Load()
	request("unknown", 200)
	request("", 200)
	if guardCalls.Load() != before {
		t.Fatal("unrecognized clients were guarded")
	}
	policy(false, false, false)
	request("llmgw_guarded-client", 200)
	if guardCalls.Load() != before {
		t.Fatal("unguarded key called guard")
	}
	if err := f.logs.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	records := f.accessRecords(t)
	var found bool
	for _, record := range records {
		if len(record.GuardChecks) == 2 && record.Status == 200 {
			found = true
			if record.TotalTokens != 14 || record.GuardChecks[0].Usage.TotalTokens != 7 {
				t.Fatalf("usage mixed=%+v", record)
			}
		}
	}
	if !found {
		t.Fatal("guard results missing from access logs")
	}
}
