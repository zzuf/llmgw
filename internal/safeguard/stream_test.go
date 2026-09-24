package safeguard

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func guardSSE(parts ...string) string { return "data: " + strings.Join(parts, "\n\ndata: ") + "\n\n" }
func guardChat(text string) string {
	return guardSSE(`{"model":"native","choices":[{"index":0,"delta":{"role":"assistant","content":"`+text+`"},"finish_reason":null}]}`, `{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`, `[DONE]`)
}
func captureTest(t *testing.T, endpoint, wire string) (*Captured, error) {
	t.Helper()
	return CaptureStream(context.Background(), strings.NewReader(wire), endpoint, "public", t.TempDir(), 256<<10, 64<<20)
}

func TestCaptureStreamWithholdsAndReplaysNormalizedSSE(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan *Captured, 1)
	failed := make(chan error, 1)
	dir := t.TempDir()
	go func() {
		c, e := CaptureStream(context.Background(), reader, "/v1/chat/completions", "public", dir, 256<<10, 64<<20)
		if e != nil {
			failed <- e
			return
		}
		done <- c
	}()
	if _, e := io.WriteString(writer, guardSSE(`{"model":"private","choices":[{"index":0,"delta":{"content":"hello"}}]}`)); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
		t.Fatal("capture returned before completion")
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(20 * time.Millisecond):
	}
	entries, e := os.ReadDir(filepath.Join(dir, "safeguard-spool"))
	if e != nil || len(entries) != 0 {
		t.Fatalf("visible temporary secret: %v %v", entries, e)
	}
	info, e := os.Stat(filepath.Join(dir, "safeguard-spool"))
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private directory: %v %v", info, e)
	}
	io.WriteString(writer, guardSSE(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, `[DONE]`))
	writer.Close()
	var c *Captured
	select {
	case c = <-done:
	case e := <-failed:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("capture hung")
	}
	defer c.Close()
	if !c.Applicable || !strings.Contains(c.Text, "hello") {
		t.Fatalf("projection %q", c.Text)
	}
	response := httptest.NewRecorder()
	ttft, e := c.Replay(context.Background(), response)
	if e != nil || ttft <= 0 || !response.Flushed || !strings.Contains(response.Body.String(), "public") || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("replay %v %v %q", ttft, e, response.Body.String())
	}
}
func TestCaptureStreamAllChoicesAndToolFragments(t *testing.T) {
	wire := guardSSE(`{"choices":[{"index":0,"delta":{"content":"danger"}},{"index":1,"delta":{"content":"safe","reasoning_content":"private thought","tool_calls":[{"index":0,"id":"call1","type":"function","function":{"name":"run","arguments":"{\"cmd\":"}}]}}]}`, `{"choices":[{"index":0,"delta":{},"finish_reason":"stop"},{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"payload\"}"}}]},"finish_reason":"tool_calls"}]}`, `[DONE]`)
	c, e := captureTest(t, "/v1/chat/completions", wire)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, part := range []string{"danger", "safe", "private thought", "payload", "run"} {
		if !strings.Contains(c.Text, part) {
			t.Errorf("missing %q in %s", part, c.Text)
		}
	}
}
func TestCaptureStreamRejectsUnreviewableOrIncompleteOutput(t *testing.T) {
	cases := map[string]string{
		"missing finish":      guardSSE(`{"choices":[{"index":0,"delta":{"content":"bad"}}]}`, `[DONE]`),
		"after done":          guardChat("safe") + guardSSE(`{"choices":[{"index":0,"delta":{"content":"bad"}}]}`),
		"after choice finish": guardSSE(`{"choices":[{"index":0,"delta":{"content":"safe"},"finish_reason":"stop"}]}`, `{"choices":[{"index":0,"delta":{"content":"bad"}}]}`, `[DONE]`),
		"unknown content":     guardSSE(`{"choices":[{"index":0,"delta":{"audio":{"data":"bad"}},"finish_reason":"stop"}]}`, `[DONE]`),
		"broken tool args":    guardSSE(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"x","type":"function","function":{"name":"run","arguments":"{"}}]},"finish_reason":"tool_calls"}]}`, `[DONE]`),
		"upstream error":      guardSSE(`{"error":{"message":"SECRET"}}`),
		"unterminated event":  strings.TrimSuffix(guardChat("safe"), "\n\n"),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			c, e := captureTest(t, "/v1/chat/completions", wire)
			if c != nil {
				c.Close()
			}
			if e == nil || strings.Contains(e.Error(), "SECRET") {
				t.Fatalf("unsafe success/error: %v", e)
			}
		})
	}
}
func TestCaptureStreamBoundsAndCancellation(t *testing.T) {
	for _, limits := range [][2]int64{{10, 64 << 20}, {256 << 10, 20}} {
		c, e := CaptureStream(context.Background(), strings.NewReader(guardChat(strings.Repeat("x", 100))), "/v1/chat/completions", "public", t.TempDir(), limits[0], limits[1])
		if c != nil {
			c.Close()
		}
		var ge *Error
		if !errors.As(e, &ge) || ge.Code != "guard_limit_exceeded" {
			t.Fatalf("limit result: %v", e)
		}
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := CaptureStream(ctx, reader, "/v1/chat/completions", "public", t.TempDir(), 256<<10, 64<<20)
		done <- e
	}()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("accepted canceled stream")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock read")
	}
}
func TestCaptureStreamFramingAndFinalZeroUsage(t *testing.T) {
	wire := guardSSE(`{"model":"native","choices":[{"index":0,"delta":{"content":"日本語"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":9}}`, `{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`, `[DONE]`)
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		c, e := CaptureStream(context.Background(), iotest.OneByteReader(strings.NewReader("\ufeff"+strings.ReplaceAll(wire, "\n", ending))), "/v1/chat/completions", "public", t.TempDir(), 256<<10, 64<<20)
		if e != nil {
			t.Fatal(e)
		}
		if c.Usage.TotalTokens != 0 || c.Usage.InputTokens != 0 || c.Usage.OutputTokens != 0 || c.UpstreamTTFT <= 0 {
			t.Fatalf("usage %+v", c.Usage)
		}
		c.Close()
	}
}
func TestCaptureMessagesTextThinkingAndToolArguments(t *testing.T) {
	wire := guardSSE(`{"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"native","content":[],"usage":{"input_tokens":4,"output_tokens":0}}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"answer"}}`, `{"type":"content_block_stop","index":0}`, `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"run","input":{}}}`, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"bad\"}"}}`, `{"type":"content_block_stop","index":1}`, `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}`, `{"type":"message_stop"}`)
	c, e := captureTest(t, "/v1/messages", wire)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !strings.Contains(c.Text, "answer") || !strings.Contains(c.Text, "bad") || c.Usage.TotalTokens != 7 {
		t.Fatalf("message %q %+v", c.Text, c.Usage)
	}
	_, e = captureTest(t, "/v1/messages", strings.Replace(wire, guardSSE(`{"type":"content_block_stop","index":1}`), "", 1))
	if e == nil {
		t.Fatal("accepted incomplete tool block")
	}
}
func TestCaptureResponsesChecksDeltasAgainstTerminal(t *testing.T) {
	wire := guardSSE(`{"type":"response.created","response":{"id":"r","status":"in_progress","output":[]}}`, `{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m","role":"assistant","status":"in_progress","content":[]}}`, `{"type":"response.content_part.added","item_id":"m","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}`, `{"type":"response.output_text.delta","item_id":"m","output_index":0,"content_index":0,"delta":"answer"}`, `{"type":"response.output_text.done","item_id":"m","output_index":0,"content_index":0,"text":"answer"}`, `{"type":"response.content_part.done","item_id":"m","output_index":0,"content_index":0,"part":{"type":"output_text","text":"answer","annotations":[]}}`, `{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"m","role":"assistant","status":"completed","content":[{"type":"output_text","text":"answer","annotations":[]}]}}`, `{"type":"response.completed","response":{"id":"r","status":"completed","model":"native","output":[{"type":"message","id":"m","role":"assistant","status":"completed","content":[{"type":"output_text","text":"answer","annotations":[]}]}],"usage":{"input_tokens":2,"output_tokens":1}}}`)
	c, e := captureTest(t, "/v1/responses", wire)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !strings.Contains(c.Text, "answer") || c.Usage.TotalTokens != 3 {
		t.Fatalf("response %q %+v", c.Text, c.Usage)
	}
	for _, bad := range []string{strings.Replace(wire, `"delta":"answer"`, `"delta":"malicious"`, 1), wire + guardSSE(`{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"bad"}`), strings.Replace(wire, `"type":"response.completed"`, `"type":"response.incomplete"`, 1)} {
		c, e = captureTest(t, "/v1/responses", bad)
		if c != nil {
			c.Close()
		}
		if e == nil {
			t.Fatal("accepted mismatched/incomplete response")
		}
	}
}

func TestCaptureResponsesFunctionsAndReasoning(t *testing.T) {
	wire := guardSSE(
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"f","type":"function_call","call_id":"c","name":"run","arguments":"","status":"in_progress"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"f","output_index":0,"delta":"{\"command\":\"danger\"}"}`,
		`{"type":"response.function_call_arguments.done","item_id":"f","output_index":0,"arguments":"{\"command\":\"danger\"}"}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"id":"f","type":"function_call","call_id":"c","name":"run","arguments":"{\"command\":\"danger\"}","status":"completed"}}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"r","type":"reasoning","summary":[]}}`,
		`{"type":"response.reasoning_summary_part.added","output_index":1,"item_id":"r","summary_index":0,"part":{"type":"summary_text","text":""}}`,
		`{"type":"response.reasoning_summary_text.delta","output_index":1,"item_id":"r","summary_index":0,"delta":"secret thought"}`,
		`{"type":"response.reasoning_summary_text.done","output_index":1,"item_id":"r","summary_index":0,"text":"secret thought"}`,
		`{"type":"response.reasoning_summary_part.done","output_index":1,"item_id":"r","summary_index":0,"part":{"type":"summary_text","text":"secret thought"}}`,
		`{"type":"response.output_item.done","output_index":1,"item":{"id":"r","type":"reasoning","summary":[{"type":"summary_text","text":"secret thought"}]}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"id":"f","type":"function_call","call_id":"c","name":"run","arguments":"{\"command\":\"danger\"}","status":"completed"},{"id":"r","type":"reasoning","summary":[{"type":"summary_text","text":"secret thought"}]}]}}`,
	)
	c, e := captureTest(t, "/v1/responses", wire)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, part := range []string{"run", "danger", "secret thought"} {
		if !strings.Contains(c.Text, part) {
			t.Errorf("lost %q in %s", part, c.Text)
		}
	}
}

func TestCaptureStreamFinishedMetadataCannotBypassInspectionLimit(t *testing.T) {
	metadata := strings.Repeat("x", 2048)
	wire := guardSSE(`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[]}}`, `{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[],"metadata":"`+metadata+`"}}`, `{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","id":"m","role":"assistant","content":[],"metadata":"`+metadata+`"}]}}`)
	c, e := CaptureStream(context.Background(), strings.NewReader(wire), "/v1/responses", "public", t.TempDir(), 512, 64<<20)
	if c != nil {
		c.Close()
	}
	var ge *Error
	if !errors.As(e, &ge) || ge.Code != "guard_limit_exceeded" {
		t.Fatalf("metadata bound: %v", e)
	}
}

func TestCaptureStreamRejectsSymlinkStorage(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(dir, "safeguard-spool")); e != nil {
		t.Fatal(e)
	}
	c, e := CaptureStream(context.Background(), strings.NewReader(guardChat("safe")), "/v1/chat/completions", "public", dir, 256<<10, 64<<20)
	if c != nil {
		c.Close()
	}
	if e == nil {
		t.Fatal("accepted symlink private spool")
	}
}

func TestCaptureStreamReplayCancellationAndClosed(t *testing.T) {
	c, e := captureTest(t, "/v1/chat/completions", guardChat("safe"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	if _, e = c.Replay(ctx, w); e == nil || w.Body.Len() != 0 {
		t.Fatalf("canceled replay %v %s", e, w.Body.String())
	}
	c.Close()
	if _, e = c.Replay(context.Background(), w); e == nil {
		t.Fatal("replayed closed spool")
	}
}

func TestCaptureStreamBoundsIntermediateResponseObjects(t *testing.T) {
	wire := guardSSE(`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[]}}`, `{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[],"extension":"`+strings.Repeat("x", 2048)+`"}}`, `{"type":"response.completed","response":{"status":"completed","output":[]}}`)
	c, e := CaptureStream(context.Background(), strings.NewReader(wire), "/v1/responses", "public", t.TempDir(), 512, 64<<20)
	if c != nil {
		c.Close()
	}
	var ge *Error
	if !errors.As(e, &ge) || ge.Code != "guard_limit_exceeded" {
		t.Fatalf("intermediate state was not bounded: %v", e)
	}
}

func TestCaptureStreamLimitAppliesToProjectionNotRepeatedWireSnapshots(t *testing.T) {
	text := strings.Repeat("a", 1000)
	itemStart := `{"type":"message","id":"m","role":"assistant","content":[]}`
	part := `{"type":"output_text","text":"` + text + `","annotations":[]}`
	item := `{"type":"message","id":"m","role":"assistant","content":[` + part + `]}`
	wire := guardSSE(`{"type":"response.output_item.added","output_index":0,"item":`+itemStart+`}`, `{"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}`, `{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"`+text+`"}`, `{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"`+text+`"}`, `{"type":"response.content_part.done","output_index":0,"content_index":0,"part":`+part+`}`, `{"type":"response.output_item.done","output_index":0,"item":`+item+`}`, `{"type":"response.completed","response":{"status":"completed","output":[`+item+`]}}`)
	c, e := CaptureStream(context.Background(), strings.NewReader(wire), "/v1/responses", "public", t.TempDir(), 1500, 64<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if len(c.Text) > 1500 || !strings.Contains(c.Text, text) {
		t.Fatalf("bad bounded text %d", len(c.Text))
	}
}

func TestCaptureStreamInspectsLifecycleAndLogprobText(t *testing.T) {
	wire := guardSSE(`{"choices":[{"index":0,"delta":{"content":"safe"},"logprobs":{"content":[{"token":"unsafe alternative","top_logprobs":[]}]},"finish_reason":"stop"}]}`, `[DONE]`)
	c, e := captureTest(t, "/v1/chat/completions", wire)
	if e == nil {
		defer c.Close()
		if !strings.Contains(c.Text, "unsafe alternative") {
			t.Fatal("logprob text bypassed inspection")
		}
	}
	responseWire := guardSSE(`{"type":"response.created","response":{"output":[],"extension":"unsafe lifecycle"}}`, `{"type":"response.completed","response":{"status":"completed","output":[]}}`)
	c, e = captureTest(t, "/v1/responses", responseWire)
	if e == nil {
		defer c.Close()
		if !strings.Contains(c.Text, "unsafe lifecycle") {
			t.Fatal("lifecycle text bypassed inspection")
		}
	}
}

func TestCaptureStreamRejectsDuplicateToolArguments(t *testing.T) {
	wire := guardSSE(`{"type":"message_start","message":{"role":"assistant","content":[]}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"c","name":"run","input":{}}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"unsafe\",\"command\":\"safe\"}"}}`, `{"type":"content_block_stop","index":0}`, `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`, `{"type":"message_stop"}`)
	c, e := captureTest(t, "/v1/messages", wire)
	if c != nil {
		c.Close()
	}
	if e == nil {
		t.Fatal("duplicate argument concealed emitted unsafe content")
	}
}

func TestCaptureStreamPreservesLargeIntegersInToolArguments(t *testing.T) {
	wire := guardSSE(`{"type":"message_start","message":{"role":"assistant","content":[]}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"c","name":"run","input":{}}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"number\":9007199254740993}"}}`, `{"type":"content_block_stop","index":0}`, `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`, `{"type":"message_stop"}`)
	c, e := captureTest(t, "/v1/messages", wire)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !strings.Contains(c.Text, "9007199254740993") {
		t.Fatalf("tool number changed during inspection: %s", c.Text)
	}
}

func TestCaptureStreamRejectsUnsupportedLifecyclePayload(t *testing.T) {
	for _, extra := range []string{`"extension":{"audio":{"data":"AAAA"}}`, `"extension":{"type":"audio","data":"AAAA"}`} {
		wire := guardSSE(`{"type":"response.created","response":{"output":[],`+extra+`}}`, `{"type":"response.completed","response":{"status":"completed","output":[]}}`)
		c, e := captureTest(t, "/v1/responses", wire)
		if c != nil {
			c.Close()
		}
		var ge *Error
		if !errors.As(e, &ge) || ge.Code != "unsupported_guard_content" {
			t.Fatalf("unsupported lifecycle result: %v", e)
		}
	}
}

func TestCaptureStreamRejectsResponsesLogprobs(t *testing.T) {
	start := guardSSE(`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[]}}`)
	for _, event := range []string{`{"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","logprobs":[{"token":"unsafe"}]}}`, `{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"safe","logprobs":[{"token":"unsafe"}]}`} {
		wire := start + guardSSE(event, `{"type":"response.completed","response":{"status":"completed","output":[]}}`)
		c, e := captureTest(t, "/v1/responses", wire)
		if c != nil {
			c.Close()
		}
		var ge *Error
		if !errors.As(e, &ge) || ge.Code != "unsupported_guard_content" {
			t.Fatalf("uninspected logprobs result: %v", e)
		}
	}
}

func TestCaptureStreamDoesNotOverwriteNativeStreamEventsExtension(t *testing.T) {
	wire := guardSSE(`{"type":"response.created","response":{"output":[],"extension":"lifecycle text"}}`, `{"type":"response.completed","response":{"status":"completed","output":[],"stream_events":"unsafe final extension"}}`)
	c, e := captureTest(t, "/v1/responses", wire)
	if c != nil {
		c.Close()
	}
	var guardErr *Error
	if !errors.As(e, &guardErr) || guardErr.Code != "unsupported_guard_content" {
		t.Fatalf("native field collision was not explicitly rejected: %v", e)
	}
}
