package safeguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func TestQwenVerdictStrict(t *testing.T) {
	for _, tc := range []struct {
		stage, content, label string
		invalid               bool
	}{
		{"input", "Safety: Safe\nCategories: None", "Safe", false},
		{"input", "Safety: Unsafe\nCategories: Violent, Jailbreak", "Unsafe", false},
		{"output", "Safety: Controversial\nCategories: PII\nRefusal: No", "Controversial", false},
		{"output", "Safety: Safe\nCategories: None\nRefusal: Yes", "Safe", false},
		{"input", "Safety: Safe", "", true},
		{"input", "Safety: Safe\nSafety: Unsafe\nCategories: None", "", true},
		{"input", "Safety: Unknown\nCategories: None", "", true},
		{"input", "Safety: Safe\nCategories: Unknown", "", true},
		{"input", "Safety: Unsafe\nCategories: None, Violent", "", true},
		{"input", "Safety: Unsafe\nCategories: Violent, Violent", "", true},
		{"output", "Safety: Safe\nCategories: None", "", true},
		{"output", "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No", "", true},
		{"output", "Safety: Safe\nCategories: None\nRefusal: Maybe", "", true},
		{"input", "Here is my classification:\nSafety: Safe\nCategories: None", "", true},
	} {
		t.Run(tc.content, func(t *testing.T) {
			v, err := (qwenAdapter{}).Parse(tc.stage, tc.content)
			if (err != nil) != tc.invalid || v.Label != tc.label {
				t.Fatalf("verdict=%+v error=%v", v, err)
			}
		})
	}
}

func TestEvaluateProtocolAndUsage(t *testing.T) {
	for _, stage := range []string{"input", "output"} {
		t.Run(stage, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer upstream-secret" {
					t.Errorf("unexpected routing/auth")
				}
				var body struct {
					Model       string
					Messages    []struct{ Role, Content string }
					Stream      bool
					Temperature int
					MaxTokens   int `json:"max_tokens"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Model != "guard-model" || body.Stream || body.Temperature != 0 || body.MaxTokens != 128 || len(body.Messages) == 0 || body.Messages[0].Content != "user-context" {
					t.Errorf("unexpected guard request: %+v", body)
				}
				content := "Safety: Safe\nCategories: None"
				if stage == "output" {
					if len(body.Messages) != 2 || body.Messages[1].Role != "assistant" || body.Messages[1].Content != "assistant-answer" {
						t.Errorf("missing output context")
					}
					content += "\nRefusal: No"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}, "usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
			}))
			defer server.Close()
			binding := domain.SafeguardBinding{Safeguard: domain.Safeguard{Adapter: "qwen3guard_gen", UpstreamModelID: "guard-model", Enabled: true, Available: true}, Engine: domain.Engine{BaseURL: server.URL, AuthType: "bearer", Enabled: true}}
			verdict, err := Evaluate(context.Background(), server.Client(), binding, "upstream-secret", stage, "user-context", "assistant-answer")
			if err != nil || verdict.Label != "Safe" || verdict.Usage.TotalTokens != 15 {
				t.Fatalf("%+v %v", verdict, err)
			}
		})
	}
}

func TestEvaluateFailsClosed(t *testing.T) {
	for _, body := range []string{
		`{"choices":[{"finish_reason":"length","message":{"content":"Safety: Safe\nCategories: None"}}]}`,
		`{"choices":[{"finish_reason":"stop","message":{"content":"Safety: Safe\nCategories: None","tool_calls":[{}]}}]}`,
		`{"choices":[{"finish_reason":"stop","message":{"content":[{"text":"Safety: Safe"}]}}]}`,
		`{"choices":[{"finish_reason":"stop","message":{"content":"Safety: Safe\nCategories: None","content":"Safety: Unsafe\nCategories: Violent"}}]}`,
		`{"choices":[]}`,
		strings.Repeat("x", (64<<10)+1),
	} {
		t.Run(body[:min(len(body), 80)], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			binding := domain.SafeguardBinding{Safeguard: domain.Safeguard{Adapter: "qwen3guard_gen", UpstreamModelID: "guard", Enabled: true, Available: true}, Engine: domain.Engine{BaseURL: server.URL, Enabled: true}}
			_, err := Evaluate(context.Background(), server.Client(), binding, "", "input", "hello", "")
			var ge *Error
			wantCode := "guard_unavailable"
			if len(body) > 64<<10 {
				wantCode = "guard_limit_exceeded"
			}
			if !errors.As(err, &ge) || ge.Code != wantCode {
				t.Fatalf("expected closed error, got %v", err)
			}
		})
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := Evaluate(ctx, nil, domain.SafeguardBinding{}, "", "input", "hello", "")
	var ge *Error
	if !errors.As(err, &ge) || ge.Code != "guard_timeout" {
		t.Fatalf("deadline = %v", err)
	}
}

func TestEvaluatePreservesUsageOnInvalidVerdict(t *testing.T) {
	for _, tc := range []struct{ name, finish, content string }{
		{"unknown classification", "stop", "Safety: Unknown\nCategories: None"},
		{"truncated classification", "length", "Safety: Safe\nCategories: None"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": tc.finish, "message": map[string]any{"role": "assistant", "content": tc.content}}}, "usage": map[string]any{"prompt_tokens": 17, "completion_tokens": 9, "total_tokens": 26}})
			}))
			defer server.Close()
			binding := domain.SafeguardBinding{Safeguard: domain.Safeguard{Adapter: "qwen3guard_gen", UpstreamModelID: "guard", Enabled: true, Available: true}, Engine: domain.Engine{BaseURL: server.URL, Enabled: true}}
			verdict, err := Evaluate(context.Background(), server.Client(), binding, "", "input", "hello", "")
			var ge *Error
			if !errors.As(err, &ge) || ge.Code != "guard_unavailable" {
				t.Fatalf("invalid verdict allowed: %+v %v", verdict, err)
			}
			if verdict.Label != "" || verdict.Usage.InputTokens != 17 || verdict.Usage.OutputTokens != 9 || verdict.Usage.TotalTokens != 26 {
				t.Fatalf("usage lost or unvalidated label retained: %+v", verdict)
			}
		})
	}
}

func TestEvaluateBodyTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	binding := domain.SafeguardBinding{Safeguard: domain.Safeguard{Adapter: "qwen3guard_gen", UpstreamModelID: "guard", Enabled: true, Available: true}, Engine: domain.Engine{BaseURL: server.URL, Enabled: true}}
	_, err := Evaluate(context.Background(), client, binding, "", "input", "hello", "")
	var ge *Error
	if !errors.As(err, &ge) || ge.Code != "guard_timeout" {
		t.Fatalf("body timeout: %v", err)
	}
}

func TestEvaluateUnavailableDoesNotLeak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SERVER-SECRET", http.StatusInternalServerError)
	}))
	defer server.Close()
	binding := domain.SafeguardBinding{Safeguard: domain.Safeguard{Adapter: "qwen3guard_gen", UpstreamModelID: "guard", Enabled: true, Available: true}, Engine: domain.Engine{BaseURL: server.URL, Enabled: true}}
	_, err := Evaluate(context.Background(), server.Client(), binding, "", "input", "hello", "")
	var ge *Error
	if !errors.As(err, &ge) || ge.Code != "guard_unavailable" || strings.Contains(err.Error(), "SERVER-SECRET") {
		t.Fatalf("unsafe upstream error: %v", err)
	}
	for _, modify := range []func(*domain.SafeguardBinding){
		func(b *domain.SafeguardBinding) { b.Safeguard.Available = false },
		func(b *domain.SafeguardBinding) { b.Safeguard.Enabled = false },
		func(b *domain.SafeguardBinding) { b.Engine.Enabled = false },
		func(b *domain.SafeguardBinding) { b.Safeguard.Adapter = "unknown" },
	} {
		copy := binding
		modify(&copy)
		_, err := Evaluate(context.Background(), server.Client(), copy, "", "input", "hello", "")
		if !errors.As(err, &ge) || ge.Code != "guard_unavailable" {
			t.Fatalf("disabled guard %v", err)
		}
	}
}

type transportTimeout struct{}

func (transportTimeout) Error() string   { return "PRIVATE HOST timed out" }
func (transportTimeout) Timeout() bool   { return true }
func (transportTimeout) Temporary() bool { return true }

func TestEvaluationMapsNetworkTimeout(t *testing.T) {
	err := evaluationError(transportTimeout{})
	var ge *Error
	if !errors.As(err, &ge) || ge.Code != "guard_timeout" || ge.Status != 504 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("timeout = %v", err)
	}
}
