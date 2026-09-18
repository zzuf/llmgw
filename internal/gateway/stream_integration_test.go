package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func readEvent(reader *bufio.Reader) (string, error) {
	var event strings.Builder
	for {
		line, err := reader.ReadString('\n')
		event.WriteString(line)
		if err != nil {
			return event.String(), err
		}
		if line == "\n" {
			return event.String(), nil
		}
	}
}

func TestSSEDeliversFirstEventBeforeUpstreamCompletesAndRecordsUsage(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	releaseUpstream := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "stream-alias", []string{}, []string{})
	finished := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); f.server.ServeHTTP(w, r) }))
	defer gateway.Close()
	defer releaseUpstream()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "POST", gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"stream-alias","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	type responseResult struct {
		response *http.Response
		err      error
	}
	responses := make(chan responseResult, 1)
	go func() { response, err := gateway.Client().Do(r); responses <- responseResult{response, err} }()
	var response *http.Response
	select {
	case result := <-responses:
		if result.err != nil {
			t.Fatal(result.err)
		}
		response = result.response
	case <-time.After(2 * time.Second):
		t.Fatal("gateway buffered the stream until upstream completion")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected SSE response: %d %v", response.StatusCode, response.Header)
	}
	reader := bufio.NewReader(response.Body)
	first, err := readEvent(reader)
	if err != nil || !strings.Contains(first, `"model":"stream-alias"`) || !strings.Contains(first, "first") {
		t.Fatalf("first event=%q err=%v", first, err)
	}
	select {
	case <-finished:
		t.Fatal("upstream completed before release")
	default:
	}
	releaseUpstream()
	rest, err := io.ReadAll(reader)
	if err != nil || !strings.Contains(string(rest), "[DONE]") || strings.Contains(string(rest), "native-model") {
		t.Fatalf("remaining stream=%q err=%v", rest, err)
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not finish")
	}
	records := f.accessRecords(t)
	if len(records) != 1 {
		t.Fatalf("records=%+v", records)
	}
	record := records[0]
	if !record.Streaming || record.Status != 200 || record.ErrorCode != "" || record.TTFTMS <= 0 || record.TTFTMS > record.DurationMS || record.InputTokens != 11 || record.OutputTokens != 7 || record.TotalTokens != 18 {
		t.Fatalf("stream metrics=%+v", record)
	}
}

func TestSSEClientCancellationClosesUpstream(t *testing.T) {
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "stream-alias", []string{}, []string{})
	finished := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); f.server.ServeHTTP(w, r) }))
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "POST", gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"stream-alias","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := gateway.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readEvent(bufio.NewReader(response.Body)); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	cancel()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream cancellation did not cancel upstream")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway handler leaked after cancellation")
	}
	records := f.accessRecords(t)
	if len(records) != 1 || !records[0].Streaming || records[0].ErrorCode == "" {
		t.Fatalf("canceled request was not recorded as failure: %+v", records)
	}
}

func TestSSETruncationKeepsStartedStatusAndRecordsFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "stream-alias", []string{}, []string{})
	body := chatBody("stream-alias")
	body["stream"] = true
	w := serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", body), 200)
	if strings.Count(w.Body.String(), "event: error") != 1 || !strings.Contains(w.Body.String(), `"model":"stream-alias"`) || strings.Contains(w.Body.String(), "native-model") {
		t.Fatalf("truncated stream response=%s", w.Body.String())
	}
	records := f.accessRecords(t)
	if len(records) != 1 || records[0].Status != 200 || records[0].ErrorCode == "" {
		t.Fatalf("started stream failure not recorded: %+v", records)
	}
}

func TestSSETimeoutEndsStartedStreamAndRecordsTimeout(t *testing.T) {
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"native-model\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "stream-alias", []string{}, []string{})
	settings := domain.DefaultSettings()
	settings.RequestTimeoutSeconds = 1
	if err := f.store.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); f.server.ServeHTTP(w, r) }))
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, "POST", gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"stream-alias","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := gateway.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "event: error") {
		t.Fatalf("timeout stream status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("timed-out upstream remains connected")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed-out stream handler remains active")
	}
	records := f.accessRecords(t)
	if len(records) != 1 || records[0].ErrorCode != "timeout" || records[0].Status != 200 || records[0].DurationMS < 900 {
		t.Fatalf("timeout metrics=%+v", records)
	}
}

func TestNativeResponsesAndMessagesStreamsTrackNestedAndPartialUsage(t *testing.T) {
	cases := []struct {
		name, path, stream   string
		body                 map[string]any
		input, output, total int64
	}{
		{"responses", "/v1/responses", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"native-model\",\"usage\":{\"input_tokens\":8,\"output_tokens\":4,\"total_tokens\":12}}}\n\n", map[string]any{"model": "stream-alias", "input": "Hello", "stream": true}, 8, 4, 12},
		{"messages", "/v1/messages", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"native-model\",\"usage\":{\"input_tokens\":8,\"output_tokens\":0}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", map[string]any{"model": "stream-alias", "messages": []any{map[string]any{"role": "user", "content": "Hello"}}, "max_tokens": 20, "stream": true}, 8, 4, 12},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, test.stream)
			}))
			defer upstream.Close()
			f := newGatewayFixture(t)
			e := f.engine(t, upstream.URL, "")
			f.model(t, e, "stream-alias", []string{}, []string{})
			w := serve(t, f.server, requestJSON(t, "POST", test.path, test.body), 200)
			if !strings.Contains(w.Body.String(), `"model":"stream-alias"`) || strings.Contains(w.Body.String(), "native-model") || strings.Contains(w.Body.String(), "event: error") {
				t.Fatalf("native stream=%s", w.Body.String())
			}
			records := f.accessRecords(t)
			if len(records) != 1 || records[0].InputTokens != test.input || records[0].OutputTokens != test.output || records[0].TotalTokens != test.total || records[0].ErrorCode != "" {
				t.Fatalf("native stream usage=%+v", records)
			}
		})
	}
}

func TestSSEFinalUsageCanCorrectEarlierCountsToZero(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"native-model\",\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1,\"total_tokens\":5}}\n\ndata: {\"model\":\"native-model\",\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":0,\"total_tokens\":4}}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	e := f.engine(t, upstream.URL, "")
	f.model(t, e, "stream-alias", []string{}, []string{})
	body := chatBody("stream-alias")
	body["stream"] = true
	serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", body), 200)
	records := f.accessRecords(t)
	if len(records) != 1 || records[0].InputTokens != 4 || records[0].OutputTokens != 0 || records[0].TotalTokens != 4 {
		t.Fatalf("final usage did not replace provisional counts: %+v", records)
	}
}

func TestConfiguredRequestDeadlineBoundsSlowUpload(t *testing.T) {
	f := newGatewayFixture(t)
	settings := domain.DefaultSettings()
	settings.RequestTimeoutSeconds = 1
	if err := f.store.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); f.server.ServeHTTP(w, r) }))
	defer gateway.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(gateway.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"model\":\"slow\",", strings.TrimPrefix(gateway.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		conn.Close()
		t.Fatal("request timeout did not bound a stalled JSON upload")
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("handler returned, but the socket neither sent a timeout response nor closed")
	}
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != 504 {
			t.Fatalf("slow upload status=%d want 504 or closed connection", response.StatusCode)
		}
	}
}
