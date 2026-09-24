package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOutputGuardWithholdsEntireSSEUntilVerdict(t *testing.T) {
	for _, test := range []struct {
		label  string
		status int
	}{{"Safe", 200}, {"Unsafe", 403}} {
		t.Run(test.label, func(t *testing.T) {
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			releaseGuard := func() { once.Do(func() { close(release) }) }
			defer releaseGuard()
			guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				close(reached)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				guardReply(w, test.label, true)
			}))
			defer guard.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"unreleased output\"},\"finish_reason\":null}]}\n\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n")
			}))
			defer upstream.Close()
			f := newGatewayFixture(t)
			a := signIn(t, f, true, "owner", administratorPassword, nil)
			g := createGuard(t, f, a, f.engine(t, guard.URL, ""))
			f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{})
			k := f.key(t, "guarded", "llmgw_stream-client")
			serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": k.Name, "enabled": true, "output_safeguard_id": g.ID}), 200)
			completed := make(chan struct{})
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(completed); f.server.ServeHTTP(w, r) }))
			defer gateway.Close()
			defer releaseGuard()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			r, err := http.NewRequestWithContext(ctx, "POST", gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"chat","stream":true,"messages":[{"role":"user","content":"Hello"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer llmgw_stream-client")
			type result struct {
				response *http.Response
				err      error
			}
			response := make(chan result, 1)
			go func() { resp, err := gateway.Client().Do(r); response <- result{resp, err} }()
			select {
			case <-reached:
			case <-ctx.Done():
				t.Fatal("output guard did not run")
			}
			select {
			case early := <-response:
				if early.response != nil {
					early.response.Body.Close()
				}
				t.Fatalf("response began before verdict: %+v", early)
			case <-time.After(50 * time.Millisecond):
			}
			releaseGuard()
			var got result
			select {
			case got = <-response:
			case <-ctx.Done():
				t.Fatal("guarded response stalled")
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			defer got.response.Body.Close()
			body, err := io.ReadAll(got.response.Body)
			if err != nil || got.response.StatusCode != test.status {
				t.Fatalf("response status=%d body=%s err=%v", got.response.StatusCode, body, err)
			}
			if test.status == 200 {
				if !strings.Contains(string(body), "unreleased output") || !strings.Contains(string(body), "[DONE]") || strings.Contains(string(body), "native-model") {
					t.Fatalf("replay=%s", body)
				}
			} else if strings.Contains(string(body), "unreleased output") || !strings.Contains(string(body), "guard_rejected") {
				t.Fatalf("unsafe output leaked=%s", body)
			}
			select {
			case <-completed:
			case <-ctx.Done():
				t.Fatal("handler stalled")
			}
			records := f.accessRecords(t)
			if len(records) != 1 || records[0].TotalTokens != 6 || len(records[0].GuardChecks) != 1 {
				t.Fatalf("records=%+v", records)
			}
			if test.status == 200 && (records[0].TTFTMS < 50 || records[0].UpstreamTTFTMS >= records[0].TTFTMS) {
				t.Fatalf("TTFT omitted guard delay=%+v", records[0])
			}
			if test.status != 200 && records[0].TTFTMS != 0 {
				t.Fatal("rejected output recorded a client token")
			}
			log, err := os.ReadFile(filepath.Join(f.dir, "logs", "access.log"))
			if err != nil || strings.Contains(string(log), "unreleased output") {
				t.Fatalf("generated text persisted in access log: %v", err)
			}
			files, err := os.ReadDir(filepath.Join(f.dir, "safeguard-spool"))
			if err != nil || len(files) != 0 {
				t.Fatalf("spool residue=%v %v", files, err)
			}
		})
	}
}

func TestInputOnlyGuardPreservesRealtimeSSE(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	releaseUpstream := func() { once.Do(func() { close(release) }) }
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		guardReply(w, "Safe", false)
	}))
	defer guard.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"early\"}}]}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	g := createGuard(t, f, a, f.engine(t, guard.URL, ""))
	f.model(t, f.engine(t, upstream.URL, ""), "chat", []string{}, []string{})
	k := f.key(t, "input-only", "llmgw_input-only")
	serve(t, f.server, a.request(t, "PUT", "/admin/api/keys/"+k.ID, map[string]any{"name": k.Name, "enabled": true, "input_safeguard_id": g.ID}), 200)
	gateway := httptest.NewServer(f.server)
	defer gateway.Close()
	defer releaseUpstream()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "POST", gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"chat","stream":true,"messages":[{"role":"user","content":"Hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer llmgw_input-only")
	response, err := gateway.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	buf := make([]byte, 256)
	n, err := response.Body.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "early") {
		t.Fatalf("first event=%s err=%v", buf[:n], err)
	}
	releaseUpstream()
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
}
