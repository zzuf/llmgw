package engine

import (
	"bytes"
	"encoding/json"
	"math"

	"llmgw/internal/domain"
)

type usagePresence struct{ input, output, total bool }

// NormalizeResponse rewrites only protocol-level model fields. Tool arguments,
// generated content, metadata, and other user-controlled objects remain untouched.
func NormalizeResponse(data []byte, alias string) ([]byte, domain.Usage, error) {
	normalized, usage, _, err := normalizeResponse(data, alias)
	return normalized, usage, err
}

func normalizeResponse(data []byte, alias string) ([]byte, domain.Usage, usagePresence, error) {
	object, err := decodeObject(bytes.NewReader(data))
	if err != nil {
		return nil, domain.Usage{}, usagePresence{}, upstreamError("Upstream returned malformed JSON")
	}
	if hasUpstreamError(object) {
		return nil, domain.Usage{}, usagePresence{}, upstreamError("Upstream engine reported a generation failure")
	}
	var usage domain.Usage
	var presence usagePresence
	model, _ := json.Marshal(alias)
	if _, ok := object["model"]; ok {
		object["model"] = model
	}
	if err = readUsage(object["usage"], &usage, &presence); err != nil {
		return nil, domain.Usage{}, usagePresence{}, err
	}
	// response.* event envelopes and Anthropic message_start carry a protocol
	// object here. Do not recursively visit arbitrary object trees.
	for _, key := range []string{"response", "message"} {
		raw, ok := object[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) != nil || nested == nil {
			continue
		}
		if hasUpstreamError(nested) {
			return nil, domain.Usage{}, usagePresence{}, upstreamError("Upstream engine reported a generation failure")
		}
		if _, ok = nested["model"]; ok {
			nested["model"] = model
		}
		if err = readUsage(nested["usage"], &usage, &presence); err != nil {
			return nil, domain.Usage{}, usagePresence{}, err
		}
		object[key], err = json.Marshal(nested)
		if err != nil {
			return nil, domain.Usage{}, usagePresence{}, upstreamError("Cannot normalize upstream response")
		}
	}
	if !presence.total {
		usage.TotalTokens = safeTotal(usage.InputTokens, usage.OutputTokens)
	}
	normalized, err := json.Marshal(object)
	if err != nil {
		return nil, domain.Usage{}, usagePresence{}, upstreamError("Cannot normalize upstream response")
	}
	return normalized, usage, presence, nil
}
func hasUpstreamError(object map[string]json.RawMessage) bool {
	if raw, ok := object["error"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	switch stringField(object, "type") {
	case "error", "response.failed":
		return true
	}
	return stringField(object, "status") == "failed"
}
func readUsage(raw json.RawMessage, usage *domain.Usage, presence *usagePresence) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return upstreamError("Upstream returned invalid token usage")
	}
	for _, field := range []struct {
		key     string
		target  *int64
		present *bool
	}{
		{"prompt_tokens", &usage.InputTokens, &presence.input}, {"input_tokens", &usage.InputTokens, &presence.input},
		{"completion_tokens", &usage.OutputTokens, &presence.output}, {"output_tokens", &usage.OutputTokens, &presence.output},
		{"total_tokens", &usage.TotalTokens, &presence.total},
	} {
		if value, ok := fields[field.key]; ok {
			var tokens int64
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &tokens) != nil || tokens < 0 {
				return upstreamError("Upstream returned invalid token usage")
			}
			*field.target = tokens
			*field.present = true
		}
	}
	return nil
}
func safeTotal(input, output int64) int64 {
	if input > math.MaxInt64-output {
		return math.MaxInt64
	}
	return input + output
}
