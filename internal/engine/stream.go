package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"llmgw/internal/domain"
)

const maxEventBytes = 8 << 20

// Stream forwards one SSE event at a time and flushes each event. It owns no
// whole-response buffer. Cancellation closes an upstream body when it is a Closer.
// On an upstream failure it emits one sanitized SSE error before returning err;
// the caller must record failure without writing a second error or HTTP status.
// onEvent receives cumulative usage, including partial Anthropic usage updates.
func Stream(ctx context.Context, w http.ResponseWriter, body io.Reader, alias string, onEvent func(domain.Usage)) (ttft time.Duration, err error) {
	started := time.Now()
	if body == nil {
		return 0, upstreamError("Upstream stream is unavailable")
	}
	if closer, ok := body.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	defer func() {
		if err != nil {
			_, _ = io.WriteString(w, "event: error\ndata: {\"error\":{\"message\":\"Upstream stream failed\",\"type\":\"gateway_error\",\"code\":\"upstream_error\"}}\n\n")
			_ = controller.Flush()
		}
	}()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), maxEventBytes+1)
	scanner.Split(sseLines())
	var event []string
	eventSize := 0
	var cumulative domain.Usage
	complete := false
	firstLine := true
	firstWrite := true
	dispatch := func() error {
		if len(event) == 0 {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var dataLines []string
		eventType := ""
		for _, line := range event {
			field, value := sseField(line)
			switch field {
			case "data":
				dataLines = append(dataLines, value)
			case "event":
				eventType = value
			}
		}
		if eventType == "error" || eventType == "response.failed" {
			return upstreamError("Upstream engine reported a streaming failure")
		}
		joined := strings.Join(dataLines, "\n")
		replacement := dataLines
		if strings.TrimSpace(joined) != "" {
			if ttft == 0 {
				ttft = time.Since(started)
				if ttft == 0 {
					ttft = time.Nanosecond
				}
			}
			if strings.TrimSpace(joined) == "[DONE]" {
				complete = true
			} else {
				normalized, usage, presence, normalizeErr := normalizeResponse([]byte(joined), alias)
				if normalizeErr != nil {
					return normalizeErr
				}
				object, _ := decodeObject(bytes.NewReader(normalized))
				switch stringField(object, "type") {
				case "response.completed", "response.incomplete", "message_stop":
					complete = true
				}
				if presence.input {
					cumulative.InputTokens = usage.InputTokens
				}
				if presence.output {
					cumulative.OutputTokens = usage.OutputTokens
				}
				if presence.total {
					cumulative.TotalTokens = usage.TotalTokens
				} else if presence.input || presence.output {
					cumulative.TotalTokens = safeTotal(cumulative.InputTokens, cumulative.OutputTokens)
				}
				if onEvent != nil {
					onEvent(cumulative)
				}
				replacement = make([]string, len(dataLines))
				replacement[0] = string(normalized)
				if len(replacement) > 1 {
					// Keep the original count and positions of data fields. A newline before
					// the final object brace is legal JSON whitespace; intervening empty data
					// fields preserve multiline framing without expanding deeply nested JSON.
					replacement[0] = strings.TrimSuffix(replacement[0], "}")
					replacement[len(replacement)-1] = "}"
				}
			}
		}
		var output bytes.Buffer
		dataIndex := 0
		for _, line := range event {
			field, _ := sseField(line)
			if field == "data" {
				output.WriteString("data: ")
				output.WriteString(replacement[dataIndex])
				dataIndex++
			} else {
				output.WriteString(line)
			}
			output.WriteByte('\n')
		}
		output.WriteByte('\n')
		payload := output.Bytes()
		if firstWrite && bytes.HasPrefix(payload, []byte("\ufeff")) {
			// A second BOM is an ordinary character, not another signature. Keep
			// it away from the beginning of the forwarded stream, where a client
			// would otherwise strip it and reinterpret an unknown field as data.
			payload = append([]byte(": gateway\n"), payload...)
		}
		if _, writeErr := w.Write(payload); writeErr != nil {
			return errors.New("Unable to write downstream stream")
		}
		firstWrite = false
		if flushErr := controller.Flush(); flushErr != nil {
			return errors.New("Unable to flush downstream stream")
		}
		return nil
	}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ttft, ctx.Err()
		}
		line := scanner.Text()
		if firstLine {
			line = strings.TrimPrefix(line, "\ufeff")
			firstLine = false
		}
		if line == "" {
			if err = dispatch(); err != nil {
				return ttft, err
			}
			event = nil
			eventSize = 0
			continue
		}
		eventSize += len(line) + 1
		if eventSize > maxEventBytes {
			return ttft, upstreamError("Upstream SSE event exceeded the size limit")
		}
		event = append(event, line)
	}
	if ctx.Err() != nil {
		return ttft, ctx.Err()
	}
	if scanner.Err() != nil {
		return ttft, upstreamError("Upstream SSE stream could not be read")
	}
	if len(event) != 0 || !complete {
		return ttft, upstreamError("Upstream SSE stream ended before completion")
	}
	return ttft, nil
}

// sseLines accepts all WHATWG event-stream line endings. A CR terminates a
// line immediately; an optional following LF is consumed on the next scan,
// even when the bytes arrive in separate reads. Waiting for a byte after CR
// would delay flushing complete events on a live connection.
func sseLines() bufio.SplitFunc {
	skipLF := false
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		start := 0
		if skipLF && len(data) > 0 {
			skipLF = false
			if data[0] == '\n' {
				start = 1
			}
		}
		for i := start; i < len(data); i++ {
			switch data[i] {
			case '\r':
				skipLF = true
				return i + 1, data[start:i], nil
			case '\n':
				return i + 1, data[start:i], nil
			}
		}
		if atEOF && len(data) > start {
			return len(data), data[start:], nil
		}
		return start, nil, nil
	}
}

func sseField(line string) (string, string) {
	field, value, found := strings.Cut(line, ":")
	if !found {
		return field, ""
	}
	return field, strings.TrimPrefix(value, " ")
}
