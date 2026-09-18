package logging

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactPromptPreservesConversationAndRemovesBinary(t *testing.T) {
	binary := strings.Repeat("aGVsbG8=", 1024)
	prompt := map[string]any{"messages": []any{
		map[string]any{"role": "system", "content": "You are helpful."},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "Describe this image."},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + binary}},
			map[string]any{"type": "input_audio", "input_audio": map[string]any{"data": binary, "format": "wav"}},
			map[string]any{"type": "document", "source": map[string]any{"type": "base64", "data": binary, "media_type": "application/pdf"}},
		}},
		map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"function": map[string]any{"name": "weather", "arguments": "{\"city\":\"Tokyo\"}"}}}},
		map[string]any{"role": "tool", "content": "20 degrees"},
	}, "attachments": []any{map[string]any{"name": "x.pdf", "data": binary}}, "b64_json": "c2VjcmV0"}
	got, err := json.Marshal(RedactPrompt(prompt))
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{"You are helpful.", "Describe this image.", "20 degrees", "weather", "Tokyo"} {
		if !strings.Contains(string(got), preserved) {
			t.Errorf("ordinary prompt missing %q: %s", preserved, got)
		}
	}
	for _, secret := range []string{binary, "c2VjcmV0", "data:image/png;base64"} {
		if strings.Contains(string(got), secret) {
			t.Errorf("binary payload leaked")
		}
	}
	if len(got) > 2000 || !strings.Contains(string(got), "bytes") {
		t.Errorf("expected compact byte markers: %s", got)
	}
	original, _ := json.Marshal(prompt)
	if !strings.Contains(string(original), binary) {
		t.Fatal("redaction mutated caller input")
	}
}

func TestRedactPromptHandlesRawBytesEmbeddedURLsAndTypedValues(t *testing.T) {
	type payload struct {
		Caption string `json:"caption"`
		Data    []byte `json:"data"`
	}
	input := map[string]any{
		"raw":      []byte("private binary"),
		"typed":    payload{"keep caption", []byte("private typed binary")},
		"inline":   "before data:application/pdf;base64,c2VjcmV0 after",
		"ordinary": "The database value is data: useful, not a data URI.",
		"url":      "https://example.test/image.png",
		"raw_json": json.RawMessage(`{"type":"input_file","file_data":"c2VjcmV0"}`),
	}
	got, err := json.Marshal(RedactPrompt(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private binary", "private typed binary", "c2VjcmV0"} {
		if strings.Contains(string(got), secret) {
			t.Errorf("leaked %q: %s", secret, got)
		}
	}
	for _, want := range []string{"before ", " after", "keep caption", "https://example.test/image.png", "The database value is data: useful"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
}

func TestRedactShortBinaryFieldsAndDataURLsWithoutMediaType(t *testing.T) {
	input := map[string]any{"image": "c2VjcmV0", "audio": "c2VjcmV0", "file": "data:;base64,c2VjcmV0", "text": "before data:,sensitive after", "source": map[string]any{"type": "image", "source": "https://example.test/image.png"}}
	got, err := json.Marshal(RedactPrompt(input))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "c2VjcmV0") || strings.Contains(string(got), "sensitive") {
		t.Fatalf("binary leaked: %s", got)
	}
	if !strings.Contains(string(got), "https://example.test/image.png") {
		t.Fatalf("remote URL lost: %s", got)
	}
}

func TestRedactionMarkersCountDecodedBytes(t *testing.T) {
	for _, input := range []any{
		"data:image/png;base64,aGVsbG8=",
		map[string]any{"image": "data:image/png;base64,aGVsbG8="},
		map[string]any{"b64_json": "aGVsbG8=\n"},
	} {
		got, err := json.Marshal(RedactPrompt(input))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), "5 bytes") {
			t.Errorf("incorrect byte count: %s", got)
		}
	}
	got := RedactPrompt("https://example.test/?image=data:image/png;base64,c2VjcmV0")
	if strings.Contains(got.(string), "c2VjcmV0") {
		t.Fatalf("embedded data URL leaked: %s", got)
	}
}
