package safeguard

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"llmgw/internal/domain"
	"llmgw/internal/engine"
)

// CaptureStream normalizes to an unlinked disk spool before inspecting the full
// stream. The existing unguarded streaming path is intentionally unchanged.
func CaptureStream(ctx context.Context, body io.Reader, endpoint, alias, dir string, textLimit, spoolLimit int64) (result *Captured, err error) {
	if textLimit <= 0 || spoolLimit <= 0 {
		return nil, streamLimit()
	}
	capture, err := newCapture(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = capture.Close()
		}
	}()
	writer := &captureWriter{f: capture.file, header: make(http.Header), limit: spoolLimit}
	capture.UpstreamTTFT, err = engine.Stream(ctx, writer, body, alias, func(u domain.Usage) { capture.Usage = u })
	if writer.err != nil {
		return nil, writer.err
	}
	if ctx.Err() != nil {
		return nil, streamContext(ctx.Err())
	}
	if err != nil {
		return nil, streamFailure("Upstream stream ended before safe inspection completed")
	}
	if _, err = capture.file.Seek(0, io.SeekStart); err != nil {
		return nil, streamFailure("Cannot inspect safeguard response")
	}
	// Repeated protocol snapshots must not consume the inspection-text budget.
	// Bound retained parser state separately; Output applies the exact text limit.
	stateLimit := textLimit
	if textLimit <= (1<<63-1)/4 {
		stateLimit *= 4
	}
	state := &streamState{endpoint: endpoint, limit: stateLimit, choices: map[int]*streamChoice{}, items: map[int]*streamItem{}, blocks: map[int]*streamBlock{}}
	if err = state.read(ctx, capture.file); err != nil {
		return nil, err
	}
	final, err := state.finish()
	if err != nil {
		return nil, err
	}
	capture.Text, capture.Applicable, err = Output(endpoint, final, textLimit)
	if err != nil {
		return nil, err
	}
	return capture, nil
}

type streamChoice struct {
	message map[string]any
	tools   map[int]map[string]any
	done    bool
	reason  string
	text    string
}
type streamPart struct {
	typ, key, text string
	textDone, done bool
}
type streamItem struct {
	object                   map[string]any
	parts                    map[int]*streamPart
	summaries                map[int]*streamPart
	arguments                string
	argsSeen, argsDone, done bool
	final                    map[string]any
}
type streamBlock struct {
	object            map[string]any
	partial           string
	partialSeen, done bool
}
type streamState struct {
	endpoint       string
	limit, used    int64
	terminal       bool
	choices        map[int]*streamChoice
	items          map[int]*streamItem
	response       map[string]any
	blocks         map[int]*streamBlock
	message        map[string]any
	messageStopped bool
	observed       []any
}

func (s *streamState) spend(n int) error {
	if int64(n) > s.limit-s.used {
		return streamLimit()
	}
	s.used += int64(n)
	return nil
}
func sxMap(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok && m != nil }
func sxString(v any) (string, bool)      { s, ok := v.(string); return s, ok }
func sxInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	value, err := n.Int64()
	if err != nil || value < 0 || value > 1<<20 {
		return 0, false
	}
	return int(value), true
}

func sxKeys(m map[string]any, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			if a == k {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func sxJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func sxSorted[T any](m map[int]T) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
func sxCompleteReason(v any) bool {
	s, ok := sxString(v)
	if !ok {
		return false
	}
	switch s {
	case "stop", "tool_calls", "function_call", "end_turn", "tool_use", "stop_sequence":
		return true
	}
	return false
}
func sxAppend(m map[string]any, key string, v any) error {
	if v == nil {
		return nil
	}
	value, ok := sxString(v)
	if !ok {
		return streamUnsupported()
	}
	previous, _ := sxString(m[key])
	m[key] = previous + value
	return nil
}

func (s *streamState) read(ctx context.Context, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), (8<<20)+1)
	var lines []string
	eventSize := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return streamContext(err)
		}
		line := scanner.Text()
		if line != "" {
			eventSize += len(line) + 1
			if eventSize > 8<<20 {
				return streamLimit()
			}
			lines = append(lines, line)
			continue
		}
		if len(lines) == 0 {
			continue
		}
		if err := s.event(lines); err != nil {
			return err
		}
		lines = nil
		eventSize = 0
	}
	if scanner.Err() != nil {
		return streamFailure("Cannot inspect complete upstream events")
	}
	if len(lines) != 0 || !s.terminal {
		return streamFailure("Upstream stream is incomplete")
	}
	return nil
}
func (s *streamState) event(lines []string) error {
	var parts []string
	eventType := ""
	for _, line := range lines {
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			parts = append(parts, value)
		case "event":
			eventType = value
		case "", "id", "retry":
		default:
			return streamUnsupported()
		}
	}
	if len(parts) == 0 {
		if eventType != "" {
			return streamUnsupported()
		}
		return nil
	}
	// Once terminal, even an empty data event is forbidden. Comments may remain.
	if s.terminal {
		return streamFailure("Upstream emitted data after its terminal event")
	}
	data := strings.Join(parts, "\n")
	if strings.TrimSpace(data) == "[DONE]" {
		if s.endpoint != "/v1/chat/completions" && s.endpoint != "/v1/completions" {
			return streamFailure("Unexpected upstream terminal event")
		}
		if len(s.choices) == 0 {
			return streamFailure("Upstream stream contains no choices")
		}
		for _, choice := range s.choices {
			if !choice.done {
				return streamFailure("Upstream choice is incomplete")
			}
		}
		s.terminal = true
		return nil
	}
	decoded, decodeErr := strictJSON([]byte(data))
	object, objectOK := sxMap(decoded)
	if decodeErr != nil || !objectOK {
		return streamUnsupported()
	}
	switch s.endpoint {
	case "/v1/chat/completions", "/v1/completions":
		if eventType != "" && eventType != "message" {
			return streamUnsupported()
		}
		return s.chat(object)
	case "/v1/messages":
		typ, _ := sxString(object["type"])
		if eventType != "" && eventType != typ {
			return streamUnsupported()
		}
		return s.messages(object)
	case "/v1/responses":
		typ, _ := sxString(object["type"])
		if eventType != "" && eventType != typ {
			return streamUnsupported()
		}
		return s.responses(object)
	default:
		return streamUnsupported()
	}
}
func (s *streamState) chat(object map[string]any) error {
	if !sxKeys(object, "id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier") {
		return streamUnsupported()
	}
	choices, ok := object["choices"].([]any)
	if !ok {
		return streamUnsupported()
	}
	for _, value := range choices {
		raw, ok := sxMap(value)
		if !ok || !sxKeys(raw, "index", "delta", "text", "finish_reason", "logprobs") {
			return streamUnsupported()
		}
		if raw["logprobs"] != nil {
			return streamUnsupported()
		}
		index, ok := sxInt(raw["index"])
		if !ok {
			return streamUnsupported()
		}
		c := s.choices[index]
		if c == nil {
			if err := s.spend(64); err != nil {
				return err
			}
			c = &streamChoice{message: map[string]any{"role": "assistant", "content": ""}, tools: map[int]map[string]any{}}
			s.choices[index] = c
		}
		if c.done {
			return streamFailure("Upstream changed a completed choice")
		}
		if s.endpoint == "/v1/completions" {
			text, ok := sxString(raw["text"])
			if !ok {
				return streamUnsupported()
			}
			if err := s.spend(len(text)); err != nil {
				return err
			}
			c.text += text
		} else {
			delta, ok := sxMap(raw["delta"])
			if !ok || !sxKeys(delta, "role", "content", "refusal", "reasoning", "reasoning_content", "tool_calls", "function_call") {
				return streamUnsupported()
			}
			if role, exists := delta["role"]; exists && role != "assistant" {
				return streamUnsupported()
			}
			for _, key := range []string{"content", "refusal", "reasoning", "reasoning_content"} {
				if value, exists := delta[key]; exists && value != nil {
					text, ok := sxString(value)
					if !ok {
						return streamUnsupported()
					}
					if err := s.spend(len(text)); err != nil {
						return err
					}
					if err := sxAppend(c.message, key, value); err != nil {
						return err
					}
				}
			}
			if v, exists := delta["function_call"]; exists && v != nil {
				function, ok := sxMap(v)
				if !ok || !sxKeys(function, "name", "arguments") {
					return streamUnsupported()
				}
				target, _ := sxMap(c.message["function_call"])
				if target == nil {
					target = map[string]any{}
					c.message["function_call"] = target
				}
				if err := s.fragmentFunction(target, function); err != nil {
					return err
				}
			}
			if v, exists := delta["tool_calls"]; exists && v != nil {
				calls, ok := v.([]any)
				if !ok {
					return streamUnsupported()
				}
				for _, call := range calls {
					tool, ok := sxMap(call)
					if !ok || !sxKeys(tool, "index", "id", "type", "function") {
						return streamUnsupported()
					}
					index, ok := sxInt(tool["index"])
					if !ok {
						return streamUnsupported()
					}
					target := c.tools[index]
					if target == nil {
						if err := s.spend(64); err != nil {
							return err
						}
						target = map[string]any{"type": "function", "function": map[string]any{}}
						c.tools[index] = target
					}
					if typ, present := tool["type"]; present && typ != "function" {
						return streamUnsupported()
					}
					if id, present := tool["id"]; present {
						if _, seen := target["id"]; seen && target["id"] != id {
							return streamUnsupported()
						}
						if value, ok := sxString(id); !ok || value == "" {
							return streamUnsupported()
						} else if err := s.spend(len(value)); err != nil {
							return err
						}
						target["id"] = id
					}
					if value, present := tool["function"]; present {
						f, ok := sxMap(value)
						if !ok || !sxKeys(f, "name", "arguments") {
							return streamUnsupported()
						}
						tf, _ := sxMap(target["function"])
						if err := s.fragmentFunction(tf, f); err != nil {
							return err
						}
					}
				}
			}
		}
		if reason, present := raw["finish_reason"]; present && reason != nil {
			if !sxCompleteReason(reason) {
				return streamFailure("Upstream generation did not finish completely")
			}
			c.done = true
			c.reason = reason.(string)
		}
	}
	return nil
}
func (s *streamState) fragmentFunction(target, fragment map[string]any) error {
	for _, key := range []string{"name", "arguments"} {
		if value, present := fragment[key]; present {
			text, ok := sxString(value)
			if !ok {
				return streamUnsupported()
			}
			if err := s.spend(len(text)); err != nil {
				return err
			}
			if err := sxAppend(target, key, value); err != nil {
				return err
			}
		}
	}
	return nil
}
func sxValidFunction(f map[string]any) bool {
	name, ok := sxString(f["name"])
	if !ok || name == "" {
		return false
	}
	args, ok := sxString(f["arguments"])
	return ok && json.Valid([]byte(args))
}
func (s *streamState) finish() ([]byte, error) {
	if !s.terminal {
		return nil, streamFailure("Upstream stream is incomplete")
	}
	switch s.endpoint {
	case "/v1/chat/completions", "/v1/completions":
		values := make([]any, 0, len(s.choices))
		for _, index := range sxSorted(s.choices) {
			c := s.choices[index]
			if !c.done {
				return nil, streamFailure("Upstream choice is incomplete")
			}
			item := map[string]any{"index": index, "finish_reason": c.reason}
			if s.endpoint == "/v1/completions" {
				item["text"] = c.text
			} else {
				calls := make([]any, 0, len(c.tools))
				for _, ti := range sxSorted(c.tools) {
					tool := c.tools[ti]
					f, _ := sxMap(tool["function"])
					if tool["id"] == nil || !sxValidFunction(f) {
						return nil, streamFailure("Upstream tool call is incomplete")
					}
					calls = append(calls, tool)
				}
				if len(calls) > 0 {
					c.message["tool_calls"] = calls
				}
				if f, ok := sxMap(c.message["function_call"]); ok && !sxValidFunction(f) {
					return nil, streamFailure("Upstream function call is incomplete")
				}
				item["message"] = c.message
			}
			values = append(values, item)
		}
		return sxJSON(map[string]any{"choices": values}), nil
	case "/v1/messages":
		return sxJSON(s.message), nil
	case "/v1/responses":
		if len(s.observed) > 0 {
			// This synthetic inspection field must never replace upstream data.
			// A native collision is unsupported rather than silently dropped.
			if _, exists := s.response["stream_events"]; exists {
				return nil, streamUnsupported()
			}
			s.response["stream_events"] = s.observed
		}
		return sxJSON(s.response), nil
	}
	return nil, streamUnsupported()
}

func (s *streamState) messages(object map[string]any) error {
	typ, _ := sxString(object["type"])
	switch typ {
	case "ping":
		if !sxKeys(object, "type") {
			return streamUnsupported()
		}
		return nil
	case "message_start":
		if s.message != nil || !sxKeys(object, "type", "message") {
			return streamUnsupported()
		}
		m, ok := sxMap(object["message"])
		if !ok || m["role"] != "assistant" {
			return streamUnsupported()
		}
		content, ok := m["content"].([]any)
		if !ok || len(content) != 0 {
			return streamUnsupported()
		}
		if err := s.spend(len(sxJSON(m))); err != nil {
			return err
		}
		s.message = m
	case "content_block_start":
		if s.message == nil || s.messageStopped || !sxKeys(object, "type", "index", "content_block") {
			return streamUnsupported()
		}
		index, ok := sxInt(object["index"])
		if !ok || s.blocks[index] != nil {
			return streamUnsupported()
		}
		block, ok := sxMap(object["content_block"])
		if !ok {
			return streamUnsupported()
		}
		switch block["type"] {
		case "text":
			if !sxKeys(block, "type", "text") {
				return streamUnsupported()
			}
			if _, ok := sxString(block["text"]); !ok {
				return streamUnsupported()
			}
		case "thinking":
			if !sxKeys(block, "type", "thinking", "signature") {
				return streamUnsupported()
			}
			if _, ok := sxString(block["thinking"]); !ok {
				return streamUnsupported()
			}
		case "tool_use":
			if !sxKeys(block, "type", "id", "name", "input") {
				return streamUnsupported()
			}
		case nil:
			return streamUnsupported()
		default:
			return streamUnsupported()
		}
		if err := s.spend(len(sxJSON(block)) + 64); err != nil {
			return err
		}
		s.blocks[index] = &streamBlock{object: block}
	case "content_block_delta":
		if !sxKeys(object, "type", "index", "delta") {
			return streamUnsupported()
		}
		index, ok := sxInt(object["index"])
		if !ok {
			return streamUnsupported()
		}
		b := s.blocks[index]
		if b == nil || b.done || s.messageStopped {
			return streamFailure("Unexpected content block delta")
		}
		delta, ok := sxMap(object["delta"])
		if !ok {
			return streamUnsupported()
		}
		key := ""
		switch delta["type"] {
		case "text_delta":
			if b.object["type"] != "text" {
				return streamUnsupported()
			}
			key = "text"
		case "thinking_delta":
			if b.object["type"] != "thinking" {
				return streamUnsupported()
			}
			key = "thinking"
		case "signature_delta":
			if b.object["type"] != "thinking" {
				return streamUnsupported()
			}
			key = "signature"
		case "input_json_delta":
			if b.object["type"] != "tool_use" {
				return streamUnsupported()
			}
			key = "partial_json"
		default:
			return streamUnsupported()
		}
		if !sxKeys(delta, "type", key) {
			return streamUnsupported()
		}
		value, ok := sxString(delta[key])
		if !ok {
			return streamUnsupported()
		}
		if err := s.spend(len(value)); err != nil {
			return err
		}
		if key == "partial_json" {
			if !b.partialSeen {
				initial, ok := sxMap(b.object["input"])
				if !ok || len(initial) != 0 {
					return streamUnsupported()
				}
			}
			b.partialSeen = true
			b.partial += value
		} else {
			if err := sxAppend(b.object, key, value); err != nil {
				return err
			}
		}
	case "content_block_stop":
		if !sxKeys(object, "type", "index") {
			return streamUnsupported()
		}
		index, ok := sxInt(object["index"])
		if !ok {
			return streamUnsupported()
		}
		b := s.blocks[index]
		if b == nil || b.done {
			return streamFailure("Unexpected content block completion")
		}
		if b.partialSeen {
			decoded, decodeErr := strictJSON([]byte(b.partial))
			input, inputOK := sxMap(decoded)
			if decodeErr != nil || !inputOK {
				return streamFailure("Upstream tool arguments are incomplete")
			}
			b.object["input"] = input
		}
		b.done = true
	case "message_delta":
		if s.message == nil || s.messageStopped || !sxKeys(object, "type", "delta", "usage") {
			return streamUnsupported()
		}
		d, ok := sxMap(object["delta"])
		if !ok || !sxKeys(d, "stop_reason", "stop_sequence") {
			return streamUnsupported()
		}
		if reason := d["stop_reason"]; reason != nil {
			if !sxCompleteReason(reason) {
				return streamFailure("Upstream message did not complete")
			}
			for _, b := range s.blocks {
				if !b.done {
					return streamFailure("Upstream content block is incomplete")
				}
			}
			s.messageStopped = true
			s.message["stop_reason"] = reason
		}
	case "message_stop":
		if !sxKeys(object, "type") || s.message == nil || !s.messageStopped {
			return streamFailure("Upstream message is incomplete")
		}
		content := make([]any, 0, len(s.blocks))
		for _, index := range sxSorted(s.blocks) {
			b := s.blocks[index]
			if !b.done {
				return streamFailure("Upstream content block is incomplete")
			}
			content = append(content, b.object)
		}
		s.message["content"] = content
		s.terminal = true
	default:
		return streamUnsupported()
	}
	return nil
}

func (s *streamState) responses(object map[string]any) error {
	typ, _ := sxString(object["type"])
	// Unknown extension fields could themselves contain content, so protected
	// streams accept only the protocol fields whose meaning is understood here.
	base := []string{"type", "sequence_number"}
	allowed := func(keys ...string) bool { return sxKeys(object, append(base, keys...)...) }
	switch typ {
	case "response.created", "response.in_progress":
		if !allowed("response") {
			return streamUnsupported()
		}
		r, ok := sxMap(object["response"])
		if !ok {
			return streamUnsupported()
		}
		if err := s.spend(len(sxJSON(object))); err != nil {
			return err
		}
		s.observed = append(s.observed, r)
		if output, exists := r["output"]; exists {
			array, ok := output.([]any)
			if !ok || len(array) != 0 {
				return streamUnsupported()
			}
		}
	case "response.output_item.added":
		if !allowed("output_index", "item") {
			return streamUnsupported()
		}
		index, ok := sxInt(object["output_index"])
		if !ok || s.items[index] != nil {
			return streamUnsupported()
		}
		item, ok := sxMap(object["item"])
		if !ok {
			return streamUnsupported()
		}
		if err := s.spend(len(sxJSON(item)) + 64); err != nil {
			return err
		}
		si := &streamItem{object: item, parts: map[int]*streamPart{}, summaries: map[int]*streamPart{}}
		switch item["type"] {
		case "message":
			content, ok := item["content"].([]any)
			if !ok || len(content) != 0 {
				return streamUnsupported()
			}
		case "function_call":
			args, ok := sxString(item["arguments"])
			if !ok {
				return streamUnsupported()
			}
			si.arguments = args
		case "reasoning":
			if v, present := item["summary"]; present {
				summary, ok := v.([]any)
				if !ok || len(summary) != 0 {
					return streamUnsupported()
				}
			}
		default:
			return streamUnsupported()
		}
		s.items[index] = si
	case "response.content_part.added", "response.reasoning_summary_part.added":
		summary := typ == "response.reasoning_summary_part.added"
		key := "content_index"
		if summary {
			key = "summary_index"
		}
		if !allowed("item_id", "output_index", key, "part") {
			return streamUnsupported()
		}
		si, index, err := s.responsePartTarget(object, key)
		if err != nil {
			return err
		}
		parts := si.parts
		if summary {
			parts = si.summaries
		}
		if parts[index] != nil {
			return streamUnsupported()
		}
		part, ok := sxMap(object["part"])
		if !ok {
			return streamUnsupported()
		}
		p, err := sxNewPart(part)
		if err != nil {
			return err
		}
		if summary && p.typ != "summary_text" {
			return streamUnsupported()
		}
		if err = s.spend(len(sxJSON(part)) + 64); err != nil {
			return err
		}
		parts[index] = p
	case "response.output_text.delta", "response.refusal.delta", "response.reasoning_text.delta", "response.reasoning_summary_text.delta", "response.output_text.done", "response.refusal.done", "response.reasoning_text.done", "response.reasoning_summary_text.done":
		if object["logprobs"] != nil {
			return streamUnsupported()
		}
		summary := strings.Contains(typ, "summary")
		key := "content_index"
		if summary {
			key = "summary_index"
		}
		isDone := strings.HasSuffix(typ, ".done")
		textkey := "delta"
		partkey := "text"
		if strings.Contains(typ, "refusal") {
			partkey = "refusal"
		}
		if isDone {
			textkey = partkey
		}
		if !allowed("item_id", "output_index", key, textkey, "logprobs", "obfuscation") {
			return streamUnsupported()
		}
		si, index, err := s.responsePartTarget(object, key)
		if err != nil {
			return err
		}
		parts := si.parts
		if summary {
			parts = si.summaries
		}
		p := parts[index]
		if p == nil || p.done || p.textDone {
			return streamFailure("Unexpected response text event")
		}
		value, ok := sxString(object[textkey])
		if !ok || p.key != partkey {
			return streamUnsupported()
		}
		if isDone {
			if value != p.text {
				return streamFailure("Upstream changed previously emitted text")
			}
			p.textDone = true
		} else {
			if err := s.spend(len(value)); err != nil {
				return err
			}
			p.text += value
		}
	case "response.content_part.done", "response.reasoning_summary_part.done":
		summary := typ == "response.reasoning_summary_part.done"
		key := "content_index"
		if summary {
			key = "summary_index"
		}
		if !allowed("item_id", "output_index", key, "part") {
			return streamUnsupported()
		}
		si, index, err := s.responsePartTarget(object, key)
		if err != nil {
			return err
		}
		parts := si.parts
		if summary {
			parts = si.summaries
		}
		p := parts[index]
		if p == nil || p.done || !p.textDone {
			return streamFailure("Upstream response part is incomplete")
		}
		raw, ok := sxMap(object["part"])
		if !ok {
			return streamUnsupported()
		}
		q, err := sxNewPart(raw)
		if err != nil {
			return err
		}
		if q.typ != p.typ || q.text != p.text {
			return streamFailure("Upstream changed a response part")
		}
		p.done = true
	case "response.function_call_arguments.delta", "response.function_call_arguments.done":
		done := strings.HasSuffix(typ, ".done")
		key := "delta"
		if done {
			key = "arguments"
		}
		if !allowed("item_id", "output_index", key, "name", "obfuscation") {
			return streamUnsupported()
		}
		si, err := s.responseItem(object)
		if err != nil {
			return err
		}
		if si.object["type"] != "function_call" || si.argsDone {
			return streamUnsupported()
		}
		value, ok := sxString(object[key])
		if !ok {
			return streamUnsupported()
		}
		if name, present := object["name"]; present && name != si.object["name"] {
			return streamFailure("Upstream changed function name")
		}
		if done {
			if value != si.arguments || !json.Valid([]byte(value)) {
				return streamFailure("Upstream function arguments are incomplete")
			}
			si.argsDone = true
		} else {
			if err = s.spend(len(value)); err != nil {
				return err
			}
			si.arguments += value
			si.argsSeen = true
		}
	case "response.output_item.done":
		if !allowed("output_index", "item") {
			return streamUnsupported()
		}
		index, ok := sxInt(object["output_index"])
		if !ok {
			return streamUnsupported()
		}
		si := s.items[index]
		if si == nil || si.done {
			return streamFailure("Unexpected response item completion")
		}
		item, ok := sxMap(object["item"])
		if !ok {
			return streamUnsupported()
		}
		if err := s.verifyResponseItem(si, item); err != nil {
			return err
		}
		if err := s.spend(len(sxJSON(item))); err != nil {
			return err
		}
		si.done = true
		si.final = item
	case "response.completed":
		if !allowed("response") {
			return streamUnsupported()
		}
		r, ok := sxMap(object["response"])
		if !ok || r["status"] != "completed" {
			return streamFailure("Upstream response is incomplete")
		}
		output, ok := r["output"].([]any)
		if !ok {
			return streamUnsupported()
		}
		if len(output) != len(s.items) {
			return streamFailure("Upstream response items changed at completion")
		}
		for i, raw := range output {
			si := s.items[i]
			if si == nil || !si.done || !reflect.DeepEqual(si.final, raw) {
				return streamFailure("Upstream response items are incomplete or inconsistent")
			}
		}
		s.response = r
		s.terminal = true
	case "response.incomplete", "response.failed":
		return streamFailure("Upstream response did not complete")
	default:
		return streamUnsupported()
	}
	return nil
}
func (s *streamState) responseItem(object map[string]any) (*streamItem, error) {
	index, ok := sxInt(object["output_index"])
	if !ok {
		return nil, streamUnsupported()
	}
	si := s.items[index]
	if si == nil || si.done {
		return nil, streamFailure("Unexpected response item event")
	}
	if id, present := object["item_id"]; present && id != si.object["id"] {
		return nil, streamFailure("Upstream response item identity changed")
	}
	return si, nil
}
func (s *streamState) responsePartTarget(object map[string]any, key string) (*streamItem, int, error) {
	si, err := s.responseItem(object)
	if err != nil {
		return nil, 0, err
	}
	index, ok := sxInt(object[key])
	if !ok {
		return nil, 0, streamUnsupported()
	}
	return si, index, nil
}
func sxNewPart(raw map[string]any) (*streamPart, error) {
	typ, ok := sxString(raw["type"])
	if !ok {
		return nil, streamUnsupported()
	}
	key := "text"
	switch typ {
	case "output_text":
		if raw["logprobs"] != nil {
			return nil, streamUnsupported()
		}
		if !sxKeys(raw, "type", "text", "annotations", "logprobs") {
			return nil, streamUnsupported()
		}
		if v, present := raw["annotations"]; present {
			a, ok := v.([]any)
			if !ok || len(a) != 0 {
				return nil, streamUnsupported()
			}
		}
	case "refusal":
		key = "refusal"
		if !sxKeys(raw, "type", key) {
			return nil, streamUnsupported()
		}
	case "reasoning_text", "summary_text":
		if !sxKeys(raw, "type", key) {
			return nil, streamUnsupported()
		}
	default:
		return nil, streamUnsupported()
	}
	value, ok := sxString(raw[key])
	if !ok {
		return nil, streamUnsupported()
	}
	return &streamPart{typ: typ, key: key, text: value}, nil
}
func (s *streamState) verifyResponseItem(si *streamItem, item map[string]any) error {
	for _, key := range []string{"id", "type", "role", "name", "call_id"} {
		if before, present := si.object[key]; present && item[key] != before {
			return streamFailure("Upstream response item identity changed")
		}
	}
	if status, present := item["status"]; present && status != "completed" {
		return streamFailure("Upstream response item is incomplete")
	}
	if si.object["type"] == "function_call" {
		args, ok := sxString(item["arguments"])
		if !ok || args != si.arguments || !json.Valid([]byte(args)) || si.argsSeen && !si.argsDone {
			return streamFailure("Upstream function call is incomplete")
		}
	}
	for _, group := range []struct {
		key   string
		parts map[int]*streamPart
	}{{"content", si.parts}, {"summary", si.summaries}} {
		value, present := item[group.key]
		if !present {
			if len(group.parts) > 0 {
				return streamFailure("Upstream dropped emitted text")
			}
			continue
		}
		array, ok := value.([]any)
		if !ok || len(array) != len(group.parts) {
			return streamFailure("Upstream response content changed")
		}
		for index, raw := range array {
			part := group.parts[index]
			if part == nil || !part.done {
				return streamFailure("Upstream response part is incomplete")
			}
			m, ok := sxMap(raw)
			if !ok {
				return streamUnsupported()
			}
			p, err := sxNewPart(m)
			if err != nil {
				return err
			}
			if p.typ != part.typ || p.text != part.text {
				return streamFailure("Upstream changed emitted text")
			}
		}
	}
	// No initial field may disappear or change except evolving content/status.
	for key, value := range si.object {
		switch key {
		case "content", "summary", "arguments", "status":
			continue
		}
		if !reflect.DeepEqual(value, item[key]) {
			return streamFailure("Upstream changed a response item")
		}
	}
	return nil
}
