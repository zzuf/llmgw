package safeguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"llmgw/internal/domain"
	"llmgw/internal/engine"
)

// Adapter isolates the model-specific conversation and classification grammar.
// Adapters never reinterpret an unrecognized verdict as safe.
type Adapter interface {
	Request(stage, input, output string) (*engine.Request, error)
	Parse(stage, content string) (Verdict, error)
}

type qwenAdapter struct{}

func (qwenAdapter) Request(stage, input, output string) (*engine.Request, error) {
	if stage != "input" && stage != "output" {
		return nil, unavailable()
	}
	messages := []map[string]string{{"role": "user", "content": input}}
	if stage == "output" {
		messages = append(messages, map[string]string{"role": "assistant", "content": output})
	}
	body, err := json.Marshal(map[string]any{"model": "guard", "messages": messages, "stream": false, "temperature": 0, "max_tokens": 128})
	if err != nil {
		return nil, unavailable()
	}
	return engine.Parse("/v1/chat/completions", bytes.NewReader(body))
}

var categories = map[string]bool{
	"Violent": true, "Non-violent Illegal Acts": true, "Sexual Content or Sexual Acts": true,
	"PII": true, "Suicide & Self-Harm": true, "Unethical Acts": true, "Politically Sensitive Topics": true,
	"Copyright Violation": true, "Jailbreak": true, "None": true,
}

func (qwenAdapter) Parse(stage, content string) (Verdict, error) {
	var verdict Verdict
	if stage != "input" && stage != "output" {
		return verdict, unavailable()
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || (key != "Safety" && key != "Categories" && key != "Refusal") {
			return Verdict{}, unavailable()
		}
		if _, exists := fields[key]; exists {
			return Verdict{}, unavailable()
		}
		fields[key] = strings.TrimSpace(value)
	}
	verdict.Label = fields["Safety"]
	if verdict.Label != "Safe" && verdict.Label != "Unsafe" && verdict.Label != "Controversial" {
		return Verdict{}, unavailable()
	}
	seen := map[string]bool{}
	for _, category := range strings.Split(fields["Categories"], ",") {
		category = strings.TrimSpace(category)
		if !categories[category] || seen[category] || (stage == "output" && category == "Jailbreak") {
			return Verdict{}, unavailable()
		}
		seen[category] = true
		verdict.Categories = append(verdict.Categories, category)
	}
	if seen["None"] && len(verdict.Categories) != 1 {
		return Verdict{}, unavailable()
	}
	verdict.Refusal = fields["Refusal"]
	if stage == "output" {
		if verdict.Refusal != "Yes" && verdict.Refusal != "No" {
			return Verdict{}, unavailable()
		}
	} else if _, exists := fields["Refusal"]; exists {
		return Verdict{}, unavailable()
	}
	return verdict, nil
}

// Evaluate sends only the adapter's own request using the configured engine's
// credentials. The caller owns the moderation deadline and policy threshold.
func Evaluate(ctx context.Context, client *http.Client, binding domain.SafeguardBinding, secret string, stage, input, output string) (Verdict, error) {
	if ctx.Err() != nil {
		return Verdict{}, evaluationError(ctx.Err())
	}
	if !binding.Safeguard.Enabled || !binding.Safeguard.Available || !binding.Engine.Enabled {
		return Verdict{}, unavailable()
	}
	var adapter Adapter
	switch binding.Safeguard.Adapter {
	case "qwen3guard_gen":
		adapter = qwenAdapter{}
	default:
		return Verdict{}, unavailable()
	}
	req, err := adapter.Request(stage, input, output)
	if err != nil {
		return Verdict{}, err
	}
	resp, err := engine.New(binding.Engine.Type).Do(ctx, client, binding.Engine, secret, req, binding.Safeguard.UpstreamModelID)
	if err != nil {
		return Verdict{}, evaluationError(err)
	}
	defer resp.Body.Close()
	const maxReply = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if ctx.Err() != nil {
		return Verdict{}, evaluationError(ctx.Err())
	}
	if err != nil {
		return Verdict{}, evaluationError(err)
	}
	if len(body) > maxReply {
		return Verdict{}, limitExceeded()
	}
	value, err := strictJSON(body)
	if err != nil {
		return Verdict{}, unavailable()
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Verdict{}, unavailable()
	}
	// Token usage is independent of whether the generated classification is
	// usable. Preserve validated accounting on fail-closed classification errors.
	_, usage, err := engine.NormalizeResponse(body, "guard")
	if err != nil {
		return Verdict{}, unavailable()
	}
	accounting := Verdict{Usage: usage}
	choices, ok := object["choices"].([]any)
	if !ok || len(choices) != 1 {
		return accounting, unavailable()
	}
	choice, ok := choices[0].(map[string]any)
	if !ok || choice["finish_reason"] != "stop" {
		return accounting, unavailable()
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return accounting, unavailable()
	}
	if role, ok := message["role"]; ok && role != "assistant" {
		return accounting, unavailable()
	}
	if calls, exists := message["tool_calls"]; exists && calls != nil {
		list, ok := calls.([]any)
		if !ok || len(list) > 0 {
			return accounting, unavailable()
		}
	}
	if message["function_call"] != nil {
		return accounting, unavailable()
	}
	content, ok := message["content"].(string)
	if !ok {
		return accounting, unavailable()
	}
	verdict, err := adapter.Parse(stage, content)
	if err != nil {
		return accounting, err
	}
	verdict.Usage = usage
	return verdict, nil
}

func evaluationError(err error) error {
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return &Error{Code: "guard_timeout", Message: "Safeguard evaluation timed out", Status: 504}
	}
	return unavailable()
}

// strictJSON rejects duplicate properties, trailing values and excessively deep
// objects. A verdict or tool argument must have one unambiguous interpretation.
func strictJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readJSONValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, unsupported()
	}
	return v, nil
}

func readJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, unsupported()
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			object := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, unsupported()
				}
				if _, duplicate := object[name]; duplicate {
					return nil, unsupported()
				}
				value, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = value
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, unsupported()
			}
			return object, nil
		case '[':
			list := []any{}
			for d.More() {
				value, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, value)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, unsupported()
			}
			return list, nil
		}
		return nil, unsupported()
	default:
		return token, nil
	}
}
