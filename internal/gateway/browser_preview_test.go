package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestBrowserPreview is an opt-in browser QA server using only disposable data
// and an injected random test key. It never opens the production Keychain.
func TestBrowserPreview(t *testing.T) {
	if os.Getenv("LLMGW_BROWSER_PREVIEW") != "1" {
		t.Skip("set LLMGW_BROWSER_PREVIEW=1 for disposable browser QA")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			io.WriteString(w, `{"data":[{"id":"mock-model","name":"Browser QA mock model","capabilities":{"chat_completions":true,"responses":true,"completions":true,"embeddings":true,"rerank":true,"messages":true,"streaming":true}}]}`)
			return
		}
		io.WriteString(w, `{"id":"mock-response","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"Browser QA response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":3,"total_tokens":7}}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	f.engine(t, upstream.URL, "")
	gateway := httptest.NewServer(f.server)
	defer gateway.Close()
	fmt.Printf("BROWSER_PREVIEW_URL=%s\nBROWSER_UPSTREAM_URL=%s\n", gateway.URL, upstream.URL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(15 * time.Minute):
	}
}
