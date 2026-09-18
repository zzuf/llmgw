package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"llmgw/internal/domain"
)

func TestNormalizeOnlyProtocolModelFieldsAndUsage(t *testing.T) {
	data := []byte(`{"type":"response.completed","response":{"model":"native","usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10},"output":[{"type":"function_call","arguments":"{\"model\":\"user-value\"}"}],"metadata":{"model":"metadata-value"}}}`)
	normalized, usage, err := NormalizeResponse(data, "alias")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(normalized, &got); err != nil {
		t.Fatal(err)
	}
	response := got["response"].(map[string]any)
	if response["model"] != "alias" || response["metadata"].(map[string]any)["model"] != "metadata-value" || !strings.Contains(string(normalized), `user-value`) {
		t.Fatalf("wrong normalization %s", normalized)
	}
	if usage != (domain.Usage{InputTokens: 7, OutputTokens: 3, TotalTokens: 10}) {
		t.Fatalf("usage %+v", usage)
	}
	data = []byte(`{"model":"native","usage":{"prompt_tokens":9,"completion_tokens":2},"choices":[{"message":{"content":"hello","model":"user-content"}}]}`)
	normalized, usage, err = NormalizeResponse(data, "alias")
	if err != nil || usage.TotalTokens != 11 || !strings.Contains(string(normalized), `"model":"user-content"`) {
		t.Fatalf("normalization: %s %+v %v", normalized, usage, err)
	}
}

func TestNormalizeRejectsMalformedAndSanitizesErrors(t *testing.T) {
	for _, data := range []string{`null`, `[]`, `{"model":"m"} {}`, `{"error":{"message":"secret credential","code":"private"}}`, `{"type":"response.failed","response":{"error":{"message":"secret credential"}}}`} {
		_, _, err := NormalizeResponse([]byte(data), "alias")
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe/absent error for %s: %v", data, err)
		}
	}
}

func TestStreamPreservesEventsMultilineAndUsage(t *testing.T) {
	body := strings.NewReader(": heartbeat\r\nevent: message_start\r\nid: event1\r\nretry: 1000\r\ndata: {\"type\":\"message_start\",\r\ndata: \"message\":{\"model\":\"native\",\"usage\":{\"input_tokens\":8,\"output_tokens\":0}}}\r\n\r\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\ndata: [DONE]\n\n")
	recorder := httptest.NewRecorder()
	var usage domain.Usage
	events := 0
	ttft, err := Stream(context.Background(), recorder, body, "alias", func(u domain.Usage) { usage = u; events++ })
	if err != nil {
		t.Fatal(err)
	}
	out := recorder.Body.String()
	for _, fragment := range []string{": heartbeat", "event: message_start", "id: event1", "retry: 1000", "alias", "event: message_delta", "data: [DONE]"} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("lost %q in %s", fragment, out)
		}
	}
	if strings.Contains(out, `"native"`) || !recorder.Flushed || ttft <= 0 || usage.InputTokens != 8 || usage.OutputTokens != 4 || usage.TotalTokens != 12 || events < 2 {
		t.Fatalf("stream result %s %+v %s", out, usage, ttft)
	}
}

func TestStreamFlushesBeforeUpstreamCompletes(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	recorder := &flushSignal{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 1)}
	finished := make(chan error, 1)
	go func() { _, err := Stream(context.Background(), recorder, reader, "alias", nil); finished <- err }()
	if _, err := io.WriteString(writer, "data: {\"model\":\"native\",\"choices\":[]}\n\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recorder.flushed:
	case <-time.After(time.Second):
		t.Fatal("buffered response until completion")
	}
	if _, err := io.WriteString(writer, "data: [DONE]\n\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

type flushSignal struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
}

func (f *flushSignal) Flush() {
	f.ResponseRecorder.Flush()
	select {
	case f.flushed <- struct{}{}:
	default:
	}
}

func TestStreamCancellationClosesBody(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Stream(ctx, httptest.NewRecorder(), reader, "alias", nil); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked on upstream")
	}
}

func TestStreamErrorsDoNotLeakAndSizeIsBounded(t *testing.T) {
	for _, body := range []string{"event: error\ndata: {\"error\":\"secret-password\"}\n\n", "data: {bad-json-secret-password}\n\n", "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"secret-password\"}}}\n\n", "data: " + strings.Repeat("x", (8<<20)+1) + "\n\n"} {
		recorder := httptest.NewRecorder()
		_, err := Stream(context.Background(), recorder, strings.NewReader(body), "alias", nil)
		if err == nil || strings.Contains(recorder.Body.String(), "secret-password") || strings.Contains(err.Error(), "secret-password") || !strings.Contains(recorder.Body.String(), "upstream_error") {
			t.Fatalf("unsafe stream err=%v, output length=%d", err, recorder.Body.Len())
		}
	}
}

func TestStreamRejectsTruncatedGeneration(t *testing.T) {
	for _, body := range []string{"", ": keepalive\n\n", "data: {\"model\":\"native\",\"choices\":[]}\n\n", "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"native\"}}"} {
		recorder := httptest.NewRecorder()
		_, err := Stream(context.Background(), recorder, strings.NewReader(body), "alias", nil)
		if err == nil || !strings.Contains(recorder.Body.String(), "upstream_error") {
			t.Fatalf("accepted truncated stream: %q, %v", body, err)
		}
	}
}

func TestStreamNativeTerminalEvents(t *testing.T) {
	for _, body := range []string{"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"native\"}}\n\n", "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n"} {
		recorder := httptest.NewRecorder()
		_, err := Stream(context.Background(), recorder, strings.NewReader(body), "alias", nil)
		if err != nil {
			t.Fatalf("native completion failed: %v", err)
		}
	}
}

func TestStreamInitialBOMNormalizesAliasAndUsage(t *testing.T) {
	wire := "\ufeffdata: {\"model\":\"private-model\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n"
	recorder := httptest.NewRecorder()
	var usage domain.Usage
	_, err := Stream(context.Background(), recorder, strings.NewReader(wire), "public-alias", func(value domain.Usage) { usage = value })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(recorder.Body.String(), "private-model") || !strings.Contains(recorder.Body.String(), "public-alias") || usage.TotalTokens != 5 {
		t.Fatalf("BOM bypassed normalization: %q %+v", recorder.Body.String(), usage)
	}
}

func TestStreamInitialBOMErrorsAreSanitized(t *testing.T) {
	for _, wire := range []string{
		"\ufeffdata: {\"error\":{\"message\":\"private-secret\"}}\n\ndata: [DONE]\n\n",
		"\ufeffevent: error\rdata: {\"message\":\"private-secret\"}\r\r",
	} {
		recorder := httptest.NewRecorder()
		_, err := Stream(context.Background(), recorder, strings.NewReader(wire), "alias", nil)
		if err == nil || strings.Contains(recorder.Body.String(), "private-secret") || !strings.Contains(recorder.Body.String(), "upstream_error") {
			t.Fatalf("BOM leaked error: %q, %v", recorder.Body.String(), err)
		}
	}
}

func TestStreamSSELineEndingsAcrossEveryReadBoundary(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		wire := "\ufeff: hello" + ending + "id: 7" + ending + "retry: 1000" + ending + "data: {\"model\":\"private-model\",\"usage\":{\"input_tokens\":4}}" + ending + ending + "data: [DONE]" + ending + ending
		for split := 0; split <= len(wire); split++ {
			body := io.MultiReader(strings.NewReader(wire[:split]), strings.NewReader(wire[split:]))
			recorder := httptest.NewRecorder()
			calls := 0
			var usage domain.Usage
			_, err := Stream(context.Background(), recorder, body, "public-alias", func(value domain.Usage) { calls++; usage = value })
			output := recorder.Body.String()
			if err != nil || calls != 1 || usage.InputTokens != 4 || strings.Contains(output, "private-model") || strings.Count(output, ": hello") != 1 || strings.Count(output, "id: 7") != 1 || strings.Count(output, "retry: 1000") != 1 || strings.Count(output, "data: [DONE]") != 1 {
				t.Fatalf("ending %q split %d: %q usage=%+v calls=%d err=%v", ending, split, output, usage, calls, err)
			}
		}
	}
}

func TestStreamCarriageReturnEventFlushesWithoutWaitingForNextByte(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	recorder := &flushSignal{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 1)}
	finished := make(chan error, 1)
	go func() { _, err := Stream(context.Background(), recorder, reader, "alias", nil); finished <- err }()
	if _, err := io.WriteString(writer, "data: {\"model\":\"native\"}\r\r"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recorder.flushed:
	case <-time.After(time.Second):
		t.Fatal("CR-delimited event waits for more upstream bytes")
	}
	if _, err := io.WriteString(writer, "data: [DONE]\r\r"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestStreamOnlyStripsTheInitialBOM(t *testing.T) {
	wire := "\ufeffdata: {\"model\":\"native\"}\n\n\ufeffdata: unknown-field\n\ndata: [DONE]\n\n"
	recorder := httptest.NewRecorder()
	calls := 0
	_, err := Stream(context.Background(), recorder, strings.NewReader(wire), "alias", func(domain.Usage) { calls++ })
	if err != nil || calls != 1 || !strings.Contains(recorder.Body.String(), "\ufeffdata: unknown-field") {
		t.Fatalf("noninitial BOM was stripped: %q calls=%d err=%v", recorder.Body.String(), calls, err)
	}
}

func TestStreamMixedLineEndingsWithOneByteReads(t *testing.T) {
	wire := "\ufeff: heartbeat\r\nid: first\rdata: {\"model\":\"native\",\"text\":\"日本語\"}\n\rdata: [DONE]\r\n\r\n"
	recorder := httptest.NewRecorder()
	_, err := Stream(context.Background(), recorder, iotest.OneByteReader(strings.NewReader(wire)), "alias", nil)
	if err != nil || strings.Contains(recorder.Body.String(), "native") || !strings.Contains(recorder.Body.String(), "日本語") {
		t.Fatalf("one-byte mixed framing: %q, %v", recorder.Body.String(), err)
	}
}

func TestStreamSecondLeadingBOMCannotBecomeAClientDataField(t *testing.T) {
	wire := "\ufeff\ufeffdata: not-a-data-field\n\ndata: [DONE]\n\n"
	recorder := httptest.NewRecorder()
	_, err := Stream(context.Background(), recorder, iotest.OneByteReader(strings.NewReader(wire)), "alias", nil)
	output := recorder.Body.String()
	if err != nil || strings.HasPrefix(output, "\ufeff") || !strings.Contains(output, "\ufeffdata: not-a-data-field") {
		t.Fatalf("second BOM was reinterpreted: %q, %v", output, err)
	}
}
