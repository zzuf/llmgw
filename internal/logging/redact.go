package logging

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

var dataURL = regexp.MustCompile(`(?i)data:[a-z0-9!#$&^_.+/-]*(?:;[a-z0-9=._+-]+)*,[^\s\"'<>\x60]+`)

// RedactPrompt copies a JSON-shaped prompt, replacing embedded binary payloads
// with byte-count markers. It leaves text messages, tool calls, and remote URLs
// intact and never changes the caller's objects.
func RedactPrompt(prompt any) any { return redactValue(prompt, false, "", 0) }

func marker(n int) string { return fmt.Sprintf("[redacted binary: %d bytes]", n) }

func encodedBytes(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			n++
		}
	}
	n = n * 3 / 4
	if strings.HasSuffix(s, "==") {
		n -= 2
	} else if strings.HasSuffix(s, "=") {
		n--
	}
	if n < 0 {
		return 0
	}
	return n
}

func binaryName(name string) bool {
	switch strings.ToLower(name) {
	case "image", "image_url", "input_image", "output_image", "audio", "input_audio", "output_audio", "document", "input_document", "file", "input_file", "video", "attachment", "attachments", "base64":
		return true
	}
	return false
}

func payloadKey(key string, binary bool) bool {
	switch strings.ToLower(key) {
	case "b64_json", "base64", "base64_data", "file_data", "audio_data", "image_data", "bytes":
		return true
	case "data", "content", "body", "source":
		return binary
	}
	return false
}

func looksBase64(s string) bool {
	if len(s) < 256 {
		return false
	}
	n := 0
	for _, c := range s {
		if c == '\r' || c == '\n' {
			continue
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
			return false
		}
		n++
	}
	return n >= 256
}

func redactString(s string, binary bool, key string) string {
	redacted := dataURL.ReplaceAllStringFunc(s, func(uri string) string {
		at := strings.IndexByte(uri, ',')
		payload := uri[at+1:]
		if strings.Contains(strings.ToLower(uri[:at]), ";base64") {
			return marker(encodedBytes(payload))
		}
		return marker(len(payload))
	})
	if redacted != s {
		return redacted
	}
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		return s
	}
	if payloadKey(key, binary) || binaryName(key) || looksBase64(s) {
		return marker(encodedBytes(s))
	}
	return s
}

func redactValue(value any, binary bool, key string, depth int) any {
	if depth > 64 {
		return "[redacted: nesting limit]"
	}
	switch v := value.(type) {
	case nil:
		return nil
	case json.RawMessage:
		var parsed any
		if json.Unmarshal(v, &parsed) == nil {
			return redactValue(parsed, binary, key, depth+1)
		}
		return marker(len(v))
	case []byte:
		return marker(len(v))
	case string:
		return redactString(v, binary, key)
	case map[string]any:
		if kind, ok := v["type"].(string); ok && binaryName(kind) {
			binary = true
		}
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = redactValue(item, binary || binaryName(k), k, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue(item, binary, key, depth+1)
		}
		return out
	case bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return value
	}
	// Handle callers using typed slices, maps, and payload structs without
	// retaining their original containers (or binary backing arrays).
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return redactValue(rv.Elem().Interface(), binary, key, depth+1)
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return marker(rv.Len())
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = redactValue(rv.Index(i).Interface(), binary, key, depth+1)
		}
		return out
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			if iter.Key().Kind() == reflect.String {
				k := iter.Key().String()
				out[k] = iter.Value().Interface()
			}
		}
		return redactValue(out, binary, key, depth+1)
	case reflect.Struct:
		out := make(map[string]any)
		rt := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			out[name] = rv.Field(i).Interface()
		}
		return redactValue(out, binary, key, depth+1)
	}
	return "[redacted: unsupported value]"
}
