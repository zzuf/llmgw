// Package engine forwards protocol-native requests to configured inference engines.
package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Error is a safe, client-visible protocol or upstream HTTP failure. Status is
// the upstream HTTP status when one exists; callers map it to a gateway status.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

// Request retains unknown protocol extensions without translating protocols.
type Request struct {
	Endpoint    string
	Model       string
	Stream      bool
	Fields      map[string]json.RawMessage
	Prompt      any
	NeedsVision bool
	NeedsTools  bool
}

func invalid(message string) error {
	return &Error{Code: "invalid_request", Message: message, Status: 400}
}
func upstreamError(message string) error {
	return &Error{Code: "upstream_error", Message: message, Status: 502}
}

func decodeObject(r io.Reader) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(r)
	var fields map[string]json.RawMessage
	if err := d.Decode(&fields); err != nil || fields == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one JSON object")
	}
	return fields, nil
}

func validEndpoint(endpoint string) bool {
	switch endpoint {
	case "/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings", "/v1/rerank", "/v1/messages":
		return true
	}
	return false
}

// Parse validates the native envelope and keeps every field for lossless forwarding.
func Parse(endpoint string, r io.Reader) (*Request, error) {
	if !validEndpoint(endpoint) {
		return nil, &Error{Code: "unsupported_endpoint", Message: "This protocol endpoint is not supported", Status: 501}
	}
	fields, err := decodeObject(r)
	if err != nil {
		return nil, invalid("Request must contain exactly one JSON object")
	}
	req := &Request{Endpoint: endpoint, Fields: fields}
	if err = json.Unmarshal(fields["model"], &req.Model); err != nil || strings.TrimSpace(req.Model) == "" {
		return nil, invalid("model must be a nonempty string")
	}
	if raw, ok := fields["stream"]; ok {
		if string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &req.Stream) != nil {
			return nil, invalid("stream must be a boolean")
		}
	}
	var input any
	switch endpoint {
	case "/v1/chat/completions", "/v1/messages":
		if !validMessages(fields["messages"], endpoint == "/v1/messages") {
			return nil, invalid("messages must be a nonempty array of message objects with role and content or tool calls")
		}
		if endpoint == "/v1/messages" {
			var max int64
			if json.Unmarshal(fields["max_tokens"], &max) != nil || max <= 0 {
				return nil, invalid("max_tokens must be a positive integer for the messages protocol")
			}
			input = promptFields(fields, "messages", "system")
		} else {
			input = decodeValue(fields["messages"])
		}
	case "/v1/responses":
		if !stringOrObjects(fields["input"]) {
			return nil, invalid("input must be a string or an array of response input objects")
		}
		input = promptFields(fields, "input", "instructions")
	case "/v1/completions":
		if !validTokenInput(fields["prompt"]) {
			return nil, invalid("prompt must be a string, string array, token array, or token-array batch")
		}
		input = decodeValue(fields["prompt"])
	case "/v1/embeddings":
		if !validTokenInput(fields["input"]) {
			return nil, invalid("input must be a string, string array, token array, or token-array batch")
		}
		if req.Stream {
			return nil, invalid("The embeddings protocol does not support streaming")
		}
		input = decodeValue(fields["input"])
	case "/v1/rerank":
		var query string
		var documents []json.RawMessage
		if json.Unmarshal(fields["query"], &query) != nil || len(fields["query"]) == 0 || string(fields["query"]) == "null" {
			return nil, invalid("query must be a string")
		}
		if json.Unmarshal(fields["documents"], &documents) != nil || len(documents) == 0 {
			return nil, invalid("documents must be a nonempty array")
		}
		for _, doc := range documents {
			var value any
			if json.Unmarshal(doc, &value) != nil {
				return nil, invalid("documents must contain strings or objects")
			}
			switch value.(type) {
			case string, map[string]any:
			default:
				return nil, invalid("documents must contain strings or objects")
			}
		}
		if req.Stream {
			return nil, invalid("The rerank protocol does not support streaming")
		}
		input = promptFields(fields, "query", "documents")
	}
	req.Prompt = input
	for _, key := range []string{"tools", "functions"} {
		if raw, ok := fields[key]; ok {
			var list []map[string]json.RawMessage
			if json.Unmarshal(raw, &list) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return nil, invalid(key + " must be an array of objects")
			}
			for _, item := range list {
				if item == nil {
					return nil, invalid(key + " must be an array of objects")
				}
			}
			req.NeedsTools = req.NeedsTools || len(list) > 0
		}
	}
	inspectFeatures(input, &req.NeedsVision, &req.NeedsTools)
	return req, nil
}

func decodeValue(raw json.RawMessage) any {
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	_ = d.Decode(&value)
	return value
}
func promptFields(fields map[string]json.RawMessage, keys ...string) map[string]any {
	out := map[string]any{}
	for _, key := range keys {
		if raw, ok := fields[key]; ok {
			out[key] = decodeValue(raw)
		}
	}
	return out
}

func validMessages(raw json.RawMessage, anthropic bool) bool {
	var messages []map[string]json.RawMessage
	if json.Unmarshal(raw, &messages) != nil || len(messages) == 0 {
		return false
	}
	for _, message := range messages {
		var role string
		if json.Unmarshal(message["role"], &role) != nil || role == "" {
			return false
		}
		content, exists := message["content"]
		if !exists || bytes.Equal(bytes.TrimSpace(content), []byte("null")) {
			if anthropic || (message["tool_calls"] == nil && message["function_call"] == nil) {
				return false
			}
			continue
		}
		if !stringOrObjects(content) {
			return false
		}
	}
	return true
}
func stringOrObjects(raw json.RawMessage) bool {
	v := decodeValue(raw)
	switch value := v.(type) {
	case string:
		return true
	case []any:
		for _, item := range value {
			if _, ok := item.(map[string]any); !ok {
				return false
			}
		}
		return true
	}
	return false
}
func validTokenInput(raw json.RawMessage) bool {
	value := decodeValue(raw)
	if _, ok := value.(string); ok {
		return true
	}
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	kind := ""
	for _, item := range list {
		current := ""
		switch v := item.(type) {
		case string:
			current = "string"
		case json.Number:
			if _, err := v.Int64(); err != nil || strings.HasPrefix(v.String(), "-") {
				return false
			}
			current = "number"
		case []any:
			if len(v) == 0 {
				return false
			}
			for _, token := range v {
				n, ok := token.(json.Number)
				if !ok {
					return false
				}
				if _, err := n.Int64(); err != nil || strings.HasPrefix(n.String(), "-") {
					return false
				}
			}
			current = "batch"
		default:
			return false
		}
		if kind != "" && current != kind {
			return false
		}
		kind = current
	}
	return true
}
func inspectFeatures(value any, vision, tool *bool) {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			inspectFeatures(child, vision, tool)
		}
	case map[string]any:
		kind, _ := v["type"].(string)
		switch kind {
		case "image", "image_url", "input_image":
			*vision = true
		case "tool_use", "tool_result", "function_call", "function_call_output":
			*tool = true
		}
		if role, _ := v["role"].(string); role == "tool" || role == "function" {
			*tool = true
		}
		if calls, ok := v["tool_calls"].([]any); ok && len(calls) > 0 {
			*tool = true
		}
		if _, ok := v["function_call"]; ok {
			*tool = true
		}
		for key, child := range v {
			if key != "arguments" && key != "input" && key != "parameters" {
				inspectFeatures(child, vision, tool)
			}
		}
		// A Responses envelope has input; a tool-use block has user-defined input.
		if kind == "" {
			if child, ok := v["input"]; ok {
				inspectFeatures(child, vision, tool)
			}
		}
	}
}

// Encode substitutes only the public model selector and does not mutate Request.
func (r *Request) Encode(upstreamModel string) ([]byte, error) {
	if r == nil || strings.TrimSpace(upstreamModel) == "" {
		return nil, invalid("An upstream model is required")
	}
	fields := make(map[string]json.RawMessage, len(r.Fields))
	for k, v := range r.Fields {
		fields[k] = v
	}
	model, err := json.Marshal(upstreamModel)
	if err != nil {
		return nil, err
	}
	fields["model"] = model
	return json.Marshal(fields)
}
