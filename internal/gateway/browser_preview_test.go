package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
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
			io.WriteString(w, `{"data":[{"id":"mock-model","name":"Browser QA mock model","capabilities":{"chat_completions":true,"responses":true,"completions":true,"embeddings":true,"rerank":true,"messages":true,"streaming":true}},{"id":"Qwen3Guard-Gen-mock","name":"Browser QA safeguard model","capabilities":{"chat_completions":true}}]}`)
			return
		}
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		if body.Model == "Qwen3Guard-Gen-mock" {
			content := "Safety: Safe\nCategories: None"
			for _, message := range body.Messages {
				if strings.Contains(message.Content, "qa-unsafe-trigger") {
					content = "Safety: Unsafe\nCategories: Violent"
				}
			}
			if len(body.Messages) == 2 && body.Messages[1].Role == "assistant" {
				content += "\nRefusal: No"
			}
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12}})
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
