package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePreservesNativeResponseFields(t *testing.T) {
	r, err := Parse("/v1/responses", strings.NewReader(`{"model":"public","input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,abc"}]}],"instructions":"be brief","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"reasoning":{"effort":"high"},"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Stream || !r.NeedsTools || !r.NeedsVision {
		t.Fatalf("features: %+v", r)
	}
	b, err := r.Encode("native")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["model"]) != `"native"` || string(got["reasoning"]) != `{"effort":"high"}` || got["input"] == nil || got["messages"] != nil {
		t.Fatalf("lossy request: %s", b)
	}
	if string(r.Fields["model"]) != `"public"` {
		t.Fatal("Encode mutated request")
	}
}

func TestParseRejectsInvalidEnvelopeAndEndpointShapes(t *testing.T) {
	cases := []struct{ endpoint, body string }{
		{"/v1/chat/completions", `null`}, {"/v1/chat/completions", `[]`}, {"/v1/chat/completions", `{"model":"m","messages":[]} {}`},
		{"/v1/chat/completions", `{"model":2,"messages":[]}`}, {"/v1/chat/completions", `{"model":" ","messages":[]}`},
		{"/v1/chat/completions", `{"model":"m","messages":"bad"}`}, {"/v1/chat/completions", `{"model":"m","messages":["bad"]}`},
		{"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":"true"}`},
		{"/v1/responses", `{"model":"m","input":7}`}, {"/v1/embeddings", `{"model":"m","input":true}`},
		{"/v1/rerank", `{"model":"m","query":"x","documents":"bad"}`}, {"/v1/completions", `{"model":"m"}`},
		{"/v1/messages", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/unknown", `{"model":"m","input":"hi"}`},
	}
	for _, c := range cases {
		t.Run(c.endpoint+c.body, func(t *testing.T) {
			if _, err := Parse(c.endpoint, strings.NewReader(c.body)); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestParseNativeInputs(t *testing.T) {
	cases := []struct{ endpoint, body string }{
		{"/v1/chat/completions", `{"model":"m","messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"f","arguments":"{}"}}]}]}`},
		{"/v1/responses", `{"model":"m","input":"hello"}`},
		{"/v1/completions", `{"model":"m","prompt":[1,2,3]}`},
		{"/v1/embeddings", `{"model":"m","input":[[1,2],[3,4]],"dimensions":128}`},
		{"/v1/rerank", `{"model":"m","query":"x","documents":["a",{"text":"b"}],"top_n":1}`},
		{"/v1/messages", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"max_tokens":100,"system":"brief"}`},
	}
	for _, c := range cases {
		t.Run(c.endpoint, func(t *testing.T) {
			if _, err := Parse(c.endpoint, strings.NewReader(c.body)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
