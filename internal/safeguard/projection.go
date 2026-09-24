package safeguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"llmgw/internal/engine"
)

// Input keeps the complete native text envelope, including histories, system
// instructions, tool definitions/results and textual vendor extensions. It never
// extracts only the most recent user message or silently removes unknown content.
func Input(req *engine.Request, limit int64) (string, error) {
	if req == nil {
		return "", unsupported()
	}
	body, err := json.Marshal(req.Fields)
	if err != nil {
		return "", unsupported()
	}
	if int64(len(body)) > limit {
		return "", limitExceeded()
	}
	value, err := strictJSON(body)
	if err != nil {
		return "", unsupported()
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", unsupported()
	}
	switch req.Endpoint {
	case "/v1/chat/completions", "/v1/messages":
		if err = inspectMessages(object["messages"]); err != nil {
			return "", err
		}
	case "/v1/responses":
		switch input := object["input"].(type) {
		case string:
		case []any:
			for _, item := range input {
				if err = inspectBlock(item); err != nil {
					return "", err
				}
			}
		default:
			return "", unsupported()
		}
	case "/v1/completions":
		if !textInput(object["prompt"]) {
			return "", unsupported()
		}
	case "/v1/embeddings":
		if !textInput(object["input"]) {
			return "", unsupported()
		}
	case "/v1/rerank":
		if _, ok := object["query"].(string); !ok {
			return "", unsupported()
		}
		documents, ok := object["documents"].([]any)
		if !ok || len(documents) == 0 {
			return "", unsupported()
		}
		for _, doc := range documents {
			if err = inspectDocument(doc); err != nil {
				return "", err
			}
		}
	default:
		return "", unsupported()
	}
	if err = inspectObject(object); err != nil {
		return "", err
	}
	return encodeProjection(object, limit)
}

// Output returns a complete canonical text representation. Numeric embeddings
// and reranking scores alone require no output moderation. Unexpected textual
// extensions remain part of the projection, including on those endpoints.
func Output(endpoint string, normalized []byte, limit int64) (string, bool, error) {
	value, err := strictJSON(normalized)
	if err != nil {
		return "", false, unavailable()
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", false, unavailable()
	}
	if object["error"] != nil {
		return "", false, unavailable()
	}
	applicable := true
	switch endpoint {
	case "/v1/chat/completions", "/v1/completions":
		choices, ok := object["choices"].([]any)
		if !ok || len(choices) == 0 {
			return "", false, unavailable()
		}
		for _, raw := range choices {
			choice, ok := raw.(map[string]any)
			if !ok {
				return "", false, unavailable()
			}
			if endpoint == "/v1/chat/completions" {
				if err = inspectMessage(choice["message"]); err != nil {
					return "", false, err
				}
			} else if _, ok := choice["text"].(string); !ok {
				return "", false, unavailable()
			}
		}
	case "/v1/responses":
		if status, exists := object["status"]; exists && status != "completed" {
			return "", false, unavailable()
		}
		output, ok := object["output"].([]any)
		if !ok {
			return "", false, unavailable()
		}
		for _, item := range output {
			if err = inspectBlock(item); err != nil {
				return "", false, err
			}
		}
	case "/v1/messages":
		if err = inspectMessage(object); err != nil {
			return "", false, err
		}
	case "/v1/embeddings":
		data, ok := object["data"].([]any)
		if !ok || len(data) == 0 {
			return "", false, unavailable()
		}
		for _, raw := range data {
			item, ok := raw.(map[string]any)
			if !ok {
				return "", false, unavailable()
			}
			switch vector := item["embedding"].(type) {
			case []any:
				if len(vector) == 0 {
					return "", false, unavailable()
				}
				for _, number := range vector {
					if _, ok := number.(json.Number); !ok {
						return "", false, unavailable()
					}
				}
			case string:
				decoded, err := base64.StdEncoding.DecodeString(vector)
				if err != nil || len(decoded) == 0 || len(decoded)%4 != 0 {
					return "", false, unavailable()
				}
			default:
				return "", false, unavailable()
			}
			delete(item, "embedding")
		}
		applicable = hasOutputText(object)
	case "/v1/rerank":
		results, ok := object["results"].([]any)
		if !ok {
			return "", false, unavailable()
		}
		for _, raw := range results {
			item, ok := raw.(map[string]any)
			if !ok {
				return "", false, unavailable()
			}
			if _, ok := item["relevance_score"].(json.Number); !ok {
				return "", false, unavailable()
			}
			if document, exists := item["document"]; exists {
				if err = inspectDocument(document); err != nil {
					return "", false, err
				}
			}
		}
		applicable = hasOutputText(object)
	default:
		return "", false, unsupported()
	}
	if err = inspectObject(object); err != nil {
		return "", false, err
	}
	if !applicable {
		return "", false, nil
	}
	text, err := encodeProjection(object, limit)
	if err != nil {
		return "", false, err
	}
	return text, true, nil
}

func encodeProjection(value any, limit int64) (string, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", unsupported()
	}
	if int64(b.Len()-1) > limit {
		return "", limitExceeded()
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

func textInput(value any) bool {
	if _, ok := value.(string); ok {
		return true
	}
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, item := range list {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func inspectMessages(value any) error {
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return unsupported()
	}
	for _, message := range list {
		if err := inspectMessage(message); err != nil {
			return err
		}
	}
	return nil
}

func inspectMessage(value any) error {
	message, ok := value.(map[string]any)
	if !ok {
		return unsupported()
	}
	if role, exists := message["role"]; exists {
		switch role {
		case "system", "developer", "user", "assistant", "tool", "function":
		default:
			return unsupported()
		}
	}
	if content := message["content"]; content != nil {
		if err := inspectContent(content); err != nil {
			return err
		}
	} else if message["tool_calls"] == nil && message["function_call"] == nil && message["refusal"] == nil && message["reasoning"] == nil && message["reasoning_content"] == nil {
		return unsupported()
	}
	if calls, exists := message["tool_calls"]; exists && calls != nil {
		list, ok := calls.([]any)
		if !ok || (len(list) == 0 && message["content"] == nil && message["refusal"] == nil && message["reasoning"] == nil && message["reasoning_content"] == nil) {
			return unsupported()
		}
		for _, raw := range list {
			call, ok := raw.(map[string]any)
			if !ok || call["type"] != "function" {
				return unsupported()
			}
			if err := inspectFunctionCall(call["function"]); err != nil {
				return err
			}
		}
	}
	if call := message["function_call"]; call != nil {
		if err := inspectFunctionCall(call); err != nil {
			return err
		}
	}
	return inspectObject(message)
}

func inspectContent(value any) error {
	if _, ok := value.(string); ok {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		return unsupported()
	}
	for _, block := range list {
		if err := inspectBlock(block); err != nil {
			return err
		}
	}
	return nil
}

func inspectBlock(value any) error {
	block, ok := value.(map[string]any)
	if !ok {
		return unsupported()
	}
	kind, _ := block["type"].(string)
	switch kind {
	case "", "message":
		if _, ok := block["role"].(string); !ok {
			return unsupported()
		}
		return inspectMessage(block)
	case "text", "input_text", "output_text", "summary_text", "reasoning_text":
		if _, ok := block["text"].(string); !ok {
			return unsupported()
		}
	case "refusal":
		if _, ok := block["refusal"].(string); !ok {
			return unsupported()
		}
	case "thinking":
		if _, ok := block["thinking"].(string); !ok {
			return unsupported()
		}
	case "reasoning":
		if block["encrypted_content"] != nil {
			return unsupported()
		}
		if _, summary := block["summary"]; !summary && block["content"] == nil {
			return unsupported()
		}
		if raw, exists := block["summary"]; exists {
			if err := inspectContent(raw); err != nil {
				return err
			}
		}
	case "function_call":
		if err := inspectFunctionCall(block); err != nil {
			return err
		}
	case "function_call_output":
		if _, ok := block["output"].(string); !ok {
			return unsupported()
		}
	case "tool_use":
		if name, ok := block["name"].(string); !ok || name == "" {
			return unsupported()
		}
		if _, ok := block["input"].(map[string]any); !ok {
			return unsupported()
		}
	case "tool_result":
		if err := inspectContent(block["content"]); err != nil {
			return err
		}
	default:
		return unsupported()
	}
	return inspectObject(block)
}

func inspectFunctionCall(value any) error {
	call, ok := value.(map[string]any)
	if !ok {
		return unsupported()
	}
	if name, ok := call["name"].(string); !ok || name == "" {
		return unsupported()
	}
	args, exists := call["arguments"]
	if !exists {
		return unsupported()
	}
	if raw, ok := args.(string); ok {
		decoded, err := strictJSON([]byte(raw))
		if err != nil {
			return unsupported()
		}
		if _, ok := decoded.(map[string]any); !ok {
			return unsupported()
		}
		call["arguments"] = decoded
	} else if _, ok := args.(map[string]any); !ok {
		return unsupported()
	}
	return nil
}

func inspectDocument(value any) error {
	if _, ok := value.(string); ok {
		return nil
	}
	document, ok := value.(map[string]any)
	if !ok || !hasAnyText(document) {
		return unsupported()
	}
	return inspectObject(document)
}

// inspectObject checks reserved media/reference fields at every native protocol
// level. Arbitrary JSON inside function schemas/arguments remains data, not a
// protocol block; its complete contents still reach the guard in the projection.
func inspectObject(object map[string]any) error {
	if kind, exists := object["type"]; exists {
		switch kind {
		case "message", "text", "input_text", "output_text", "summary_text", "reasoning_text", "refusal", "thinking", "reasoning", "function", "function_call", "function_call_output", "tool_use", "tool_result", "response", "chat.completion", "text_completion", "embedding", "list", "json_object", "json_schema", "content":
		default:
			return unsupported()
		}
	}
	for key, value := range object {
		if value == nil {
			continue
		}
		switch key {
		case "previous_response_id", "conversation", "encrypted_content", "redacted_thinking",
			"image_url", "input_image", "image", "images", "input_audio", "audio", "audio_url",
			"file", "file_id", "file_data", "input_file", "attachments", "attachment", "video", "video_url",
			"blob", "binary", "input_token_ids", "prompt_token_ids":
			return unsupported()
		case "arguments", "parameters", "input_schema", "json_schema":
			continue
		case "input":
			if object["type"] == "tool_use" {
				continue
			}
		case "tools", "functions":
			list, ok := value.([]any)
			if !ok {
				return unsupported()
			}
			for _, raw := range list {
				tool, ok := raw.(map[string]any)
				if !ok {
					return unsupported()
				}
				if kind, exists := tool["type"]; exists && kind != "function" {
					return unsupported()
				}
				if err := inspectObject(tool); err != nil {
					return err
				}
			}
			continue
		case "content":
			if err := inspectContent(value); err != nil {
				return err
			}
		case "reasoning_content", "refusal", "thinking":
			if _, ok := value.(string); !ok {
				return unsupported()
			}
		}
		if err := inspectValue(value); err != nil {
			return err
		}
	}
	return nil
}

func inspectValue(value any) error {
	switch v := value.(type) {
	case map[string]any:
		return inspectObject(v)
	case []any:
		for _, child := range v {
			if err := inspectValue(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasAnyText(value any) bool {
	switch v := value.(type) {
	case string:
		return v != ""
	case []any:
		for _, item := range v {
			if hasAnyText(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if hasAnyText(item) {
				return true
			}
		}
	}
	return false
}

func hasOutputText(value any) bool {
	switch v := value.(type) {
	case string:
		return v != ""
	case []any:
		for _, item := range v {
			if hasOutputText(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			switch key {
			case "id", "object", "model", "usage", "created", "created_at", "index", "relevance_score":
				continue
			}
			if hasOutputText(item) {
				return true
			}
		}
	}
	return false
}
