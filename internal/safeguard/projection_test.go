package safeguard

import (
	"errors"
	"strings"
	"testing"

	"llmgw/internal/engine"
)

func TestInputRetainsWholeContext(t *testing.T) {
	request, err := engine.Parse("/v1/chat/completions", strings.NewReader(`{"model":"alias","messages":[{"role":"system","content":"system-secret"},{"role":"developer","content":"developer-rule"},{"role":"assistant","content":null,"tool_calls":[{"id":"x","type":"function","function":{"name":"search","arguments":"{\"query\":\"earlier-call\"}"}}]},{"role":"tool","tool_call_id":"x","content":"tool-result"},{"role":"user","content":[{"type":"text","text":"latest-question"}],"extra_note":"extension-text"}],"tools":[{"type":"function","function":{"name":"search","description":"tool-description","parameters":{"type":"object","properties":{"query":{"type":"string"}}}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	text, err := Input(request, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"system-secret", "developer-rule", "earlier-call", "tool-result", "latest-question", "extension-text", "tool-description"} {
		if !strings.Contains(text, s) {
			t.Errorf("missing %q in %s", s, text)
		}
	}
	_, err = Input(request, 32)
	var ge *Error
	if !errors.As(err, &ge) || ge.Code != "guard_limit_exceeded" {
		t.Fatalf("limit = %v", err)
	}
}

func TestInputUnsupportedContent(t *testing.T) {
	for _, tc := range []struct{ endpoint, body string }{
		{"chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/img"}}]}]}`},
		{"chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"novel_blob","text":"unknown"}]}]}`},
		{"chat/completions", `{"model":"m","messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"f","arguments":"{broken"}}]}]}`},
		{"responses", `{"model":"m","input":"hello","previous_response_id":"resp_old"}`},
		{"responses", `{"model":"m","input":"hello","conversation":{"id":"conv_old"}}`},
		{"responses", `{"model":"m","input":[{"type":"reasoning","encrypted_content":"opaque","summary":[]}]}`},
		{"completions", `{"model":"m","prompt":[100,200]}`},
		{"embeddings", `{"model":"m","input":[[100]]}`},
		{"messages", `{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","data":"raw"}}]}]}`},
	} {
		t.Run(tc.endpoint+tc.body, func(t *testing.T) {
			r, err := engine.Parse("/v1/"+tc.endpoint, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Input(r, 256<<10)
			var ge *Error
			if !errors.As(err, &ge) || ge.Code != "unsupported_guard_content" {
				t.Fatalf("expected unsupported content: %v", err)
			}
		})
	}
}

func TestOutputAllChoicesAndItems(t *testing.T) {
	for _, tc := range []struct {
		endpoint, body string
		want           []string
	}{
		{"chat/completions", `{"choices":[{"message":{"role":"assistant","content":"choice-one","reasoning_content":"private-thought"}},{"message":{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"f","arguments":"{\"x\":\"choice-two\"}"}}]}}],"native_extra":"extension-output"}`, []string{"choice-one", "private-thought", "choice-two", "extension-output"}},
		{"responses", `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"response-one"}]},{"type":"function_call","name":"f","arguments":"{\"x\":\"response-two\"}"},{"type":"reasoning","summary":[{"type":"summary_text","text":"response-thought"}]}]}`, []string{"response-one", "response-two", "response-thought"}},
		{"completions", `{"choices":[{"text":"completion-one"},{"text":"completion-two"}]}`, []string{"completion-one", "completion-two"}},
		{"messages", `{"type":"message","role":"assistant","content":[{"type":"text","text":"anthropic-text"},{"type":"thinking","thinking":"anthropic-thought"},{"type":"tool_use","id":"x","name":"f","input":{"value":"anthropic-call"}}]}`, []string{"anthropic-text", "anthropic-thought", "anthropic-call"}},
		{"rerank", `{"results":[{"index":0,"relevance_score":0.7,"document":{"text":"returned-document"}}]}`, []string{"returned-document"}},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			text, applicable, err := Output("/v1/"+tc.endpoint, []byte(tc.body), 256<<10)
			if err != nil || !applicable {
				t.Fatalf("%v %v", applicable, err)
			}
			for _, s := range tc.want {
				if !strings.Contains(text, s) {
					t.Errorf("missing %q", s)
				}
			}
		})
	}
}

func TestOutputNumericAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		endpoint, body    string
		valid, applicable bool
	}{
		{"embeddings", `{"data":[{"embedding":[0.1,0.2],"index":0}]}`, true, false},
		{"embeddings", `{"data":[{"embedding":"AACAPw==","index":0}]}`, true, false},
		{"embeddings", `{"data":[{"embedding":[0.1],"index":0}],"surprise":"text-content"}`, true, true},
		{"rerank", `{"results":[{"index":0,"relevance_score":0.3}]}`, true, false},
		{"chat/completions", `{"choices":[]}`, false, false},
		{"chat/completions", `{"choices":[{"message":{"content":[{"type":"audio","data":"abc"}]}}]}`, false, false},
		{"responses", `{"status":"completed","output":[{"type":"unknown_output","content":"hidden"}]}`, false, false},
		{"completions", `{"choices":[{"text":null}]}`, false, false},
		{"embeddings", `{"data":[{"embedding":{"unexpected":"x"}}]}`, false, false},
		{"embeddings", `{"data":[{"embedding":"this-is-text"}]}`, false, false},
		{"embeddings", `{"data":[{"embedding":"YQ=="}]}`, false, false},
		{"chat/completions", `{"choices":[{"message":{"content":"hello"}}],"native_extension":{"type":"new_audio_blob","payload":"opaque"}}`, false, false},
		{"chat/completions", `{"choices":[{"message":{"content":null,"tool_calls":[]}}]}`, false, false},
	} {
		t.Run(tc.endpoint+tc.body, func(t *testing.T) {
			_, applicable, err := Output("/v1/"+tc.endpoint, []byte(tc.body), 256<<10)
			if (err == nil) != tc.valid || applicable != tc.applicable {
				t.Fatalf("applicable %v error %v", applicable, err)
			}
		})
	}
}

func TestToolArgumentEscapesAreDecoded(t *testing.T) {
	request, err := engine.Parse("/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"f","arguments":"{\"message\":\"\\u0068\\u0061\\u0072\\u006d\"}"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	text, err := Input(request, 4096)
	if err != nil || !strings.Contains(text, "harm") {
		t.Fatalf("hidden argument: %s %v", text, err)
	}
}

func TestInputNativeTextProtocols(t *testing.T) {
	for _, tc := range []struct {
		endpoint, body string
		want           []string
	}{
		{"responses", `{"model":"m","instructions":"global instructions","input":[{"role":"developer","content":"developer input"},{"role":"user","content":[{"type":"input_text","text":"question"}]},{"type":"function_call","name":"lookup","arguments":"{\"query\":\"tool query\"}"},{"type":"function_call_output","call_id":"call","output":"tool result"}]}`, []string{"global instructions", "developer input", "question", "tool query", "tool result"}},
		{"messages", `{"model":"m","max_tokens":20,"system":[{"type":"text","text":"system instructions"}],"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"thinking history"},{"type":"tool_use","id":"call","name":"lookup","input":{"query":"tool input"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call","content":[{"type":"text","text":"tool result"}]}]}],"tools":[{"name":"lookup","description":"lookup tool","input_schema":{"type":"object","properties":{"type":{"type":"string"}}}}]}`, []string{"system instructions", "thinking history", "tool input", "tool result", "lookup tool"}},
		{"completions", `{"model":"m","prompt":["first prompt","second prompt"],"suffix":"suffix prompt"}`, []string{"first prompt", "second prompt", "suffix prompt"}},
		{"embeddings", `{"model":"m","input":["first embedding","second embedding"]}`, []string{"first embedding", "second embedding"}},
		{"rerank", `{"model":"m","query":"search query","documents":["first document",{"title":"second title","text":"second body"}]}`, []string{"search query", "first document", "second title", "second body"}},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			request, err := engine.Parse("/v1/"+tc.endpoint, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			text, err := Input(request, 256<<10)
			if err != nil {
				t.Fatal(err)
			}
			for _, needle := range tc.want {
				if !strings.Contains(text, needle) {
					t.Errorf("missing %s", needle)
				}
			}
		})
	}
}

func TestProjectionRejectsDuplicatePropertiesAndPreservesRequest(t *testing.T) {
	request, err := engine.Parse("/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"safe","content":"unsafe"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Input(request, 4096); err == nil {
		t.Fatal("accepted ambiguous content")
	}
	request, err = engine.Parse("/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"assistant","content":null,"function_call":{"name":"f","arguments":"{\"value\":\"original\"}"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	before, err := request.Encode("upstream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Input(request, 4096); err != nil {
		t.Fatal(err)
	}
	after, err := request.Encode("upstream")
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("projection mutated upstream arguments")
	}
}
