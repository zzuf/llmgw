package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"llmgw/internal/acl"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/engine"
	"llmgw/internal/logging"
)

var endpoints = map[string]string{"/v1/chat/completions": "chat_completions", "/v1/responses": "responses", "/v1/completions": "completions", "/v1/embeddings": "embeddings", "/v1/rerank": "rerank", "/v1/messages": "messages"}

func (s *Server) candidate(r *http.Request) (domain.APIKey, error) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(fields[1]) > 1024 {
		return domain.APIKey{}, nil
	}
	key, e := s.Store.KeyByHash(r.Context(), cryptoutil.HashSecret(fields[1]))
	if errors.Is(e, database.ErrNotFound) {
		return domain.APIKey{}, nil
	}
	if e != nil {
		return domain.APIKey{}, e
	}
	if !key.Enabled {
		return domain.APIKey{}, nil
	}
	return key, nil
}
func (s *Server) public(w *responseWriter, r *http.Request, requestID string) {
	// Only public API routes use wildcard CORS; administrator sessions remain same-origin.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
	start := time.Now()
	bodyConsumed := r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0
	if !bodyConsumed {
		w.Header().Set("Connection", "close")
	}
	rec := domain.AccessRecord{Timestamp: start.UTC().Format(time.RFC3339Nano), SourceIP: acl.SourceIP(r.RemoteAddr).String(), RequestID: requestID, Endpoint: r.URL.Path, Method: r.Method}
	defer func() {
		rec.Status = w.status
		rec.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		if s.Logs != nil {
			if e := s.Logs.Record(rec); e != nil {
				slog.Error("access log enqueue failed", "request_id", requestID)
			}
		}
	}()
	if r.Method == http.MethodOptions {
		// Preflight has no bearer credentials and must not depend on the database or upstream.
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		headers := strings.Join(r.Header.Values("Access-Control-Request-Headers"), ", ")
		if headers == "" {
			headers = "Authorization, Content-Type"
		}
		w.Header().Set("Access-Control-Allow-Headers", headers)
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fail := func(status int, code, msg string) {
		rec.ErrorCode = code
		if code == "timeout" {
			w.Header().Set("Connection", "close")
		}
		apiError(w, status, code, msg)
	}
	settings, e := s.Store.Settings(r.Context())
	if e != nil {
		fail(500, "internal_error", "Configuration is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(settings.RequestTimeoutSeconds)*time.Second)
	r = r.WithContext(ctx)
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	// Leave a short window to send a controlled timeout response after the read deadline.
	_ = controller.SetWriteDeadline(deadline.Add(2 * time.Second))
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now().Add(2 * time.Second))
		close(stopped)
	})
	defer func() {
		if !stop() {
			<-stopped
		}
		expired := ctx.Err() != nil || !time.Now().Before(deadline)
		cancel()
		if !bodyConsumed || expired {
			_ = controller.SetReadDeadline(time.Now())
		} else {
			_ = controller.SetReadDeadline(time.Time{})
		}
		if !expired {
			_ = controller.SetWriteDeadline(time.Time{})
		}
	}()
	key, e := s.candidate(r)
	if e != nil {
		fail(500, "internal_error", "Could not evaluate credentials")
		return
	}
	if key.ID != "" {
		rec.APIKeyID = key.ID
		rec.APIKeyName = key.Name
		rec.APIKeyTags = key.Tags
	}
	if r.URL.Path == "/v1/models" {
		if r.Method != "GET" {
			methodError(w)
			return
		}
		models, e := s.Store.ListModels(r.Context())
		if e != nil {
			fail(500, "internal_error", "Could not list models")
			return
		}
		engines, e := s.Store.ListEngines(r.Context())
		if e != nil {
			fail(500, "internal_error", "Could not list models")
			return
		}
		enabled := map[string]bool{}
		for _, en := range engines {
			enabled[en.ID] = en.Enabled
		}
		data := []map[string]any{}
		for _, m := range models {
			if m.Published && m.Available && enabled[m.EngineID] && acl.Allowed(acl.SourceIP(r.RemoteAddr), m.AllowedIPs, m.AllowedAPIKeys, key.ID) {
				data = append(data, map[string]any{"id": m.Alias, "object": "model", "created": createdUnix(m.CreatedAt), "owned_by": "llmgw"})
			}
		}
		if key.ID != "" {
			_ = s.Store.TouchAPIKey(r.Context(), key.ID)
		}
		writeJSON(w, 200, map[string]any{"object": "list", "data": data})
		return
	}
	cap, ok := endpoints[r.URL.Path]
	if !ok {
		fail(501, "unsupported_endpoint", "Endpoint is not supported")
		return
	}
	if r.Method != "POST" {
		methodError(w)
		return
	}
	req, e := engine.Parse(r.URL.Path, r.Body)
	if e != nil {
		var ne net.Error
		if ctx.Err() != nil || !time.Now().Before(deadline) || errors.As(e, &ne) && ne.Timeout() {
			fail(504, "timeout", "Request timed out")
			return
		}
		fail(400, "invalid_request", "Invalid JSON or request fields")
		return
	}
	rec.Streaming = req.Stream
	bodyConsumed = true
	w.Header().Del("Connection")
	rec.Prompt = logging.RedactPrompt(req.Prompt)
	m, e := s.Store.ModelByAlias(r.Context(), req.Model)
	if errors.Is(e, database.ErrNotFound) || e == nil && !m.Published {
		fail(404, "model_not_found", "Model not found")
		return
	}
	if e != nil {
		fail(500, "internal_error", "Could not load model")
		return
	}
	rec.ModelID = m.ID
	rec.ModelAlias = m.Alias
	rec.EngineID = m.EngineID
	rec.UpstreamModel = m.UpstreamModelID
	if !m.Available {
		fail(503, "model_unavailable", "Model is unavailable")
		return
	}
	if !acl.IPAllowed(acl.SourceIP(r.RemoteAddr), m.AllowedIPs) {
		fail(403, "forbidden", "Source IP is not allowed for this model")
		return
	}
	if len(m.AllowedAPIKeys) > 0 {
		if key.ID == "" {
			fail(401, "unauthorized", "A valid API key is required for this model")
			return
		}
		if !slices.Contains(m.AllowedAPIKeys, key.ID) {
			fail(403, "forbidden", "API key is not allowed for this model")
			return
		}
	}
	if !m.Capabilities[cap] {
		fail(501, "unsupported_endpoint", "Model does not support this endpoint")
		return
	}
	if req.Stream && !m.Capabilities["streaming"] || req.NeedsTools && !m.Capabilities["tools"] || req.NeedsVision && !m.Capabilities["vision"] {
		fail(400, "unsupported_capability", "Requested capability is not enabled for this model")
		return
	}
	en, e := s.Store.GetEngine(r.Context(), m.EngineID)
	if e != nil || !en.Enabled {
		fail(503, "engine_unavailable", "Engine is unavailable")
		return
	}
	rec.EngineName = en.Name
	secret := ""
	if len(en.SecretCipher) > 0 {
		plain, e := s.Vault.Decrypt(en.SecretCipher, "engine:"+en.ID)
		if e != nil {
			fail(500, "internal_error", "Engine credentials are unavailable")
			return
		}
		secret = string(plain)
	}
	typ := en.Type
	if typ == "auto" && en.DetectedType != "" {
		typ = en.DetectedType
	}
	resp, e := engine.New(typ).Do(ctx, s.Client, en, secret, req, m.UpstreamModelID)
	if e != nil {
		status, code, msg := upstreamFailure(e, ctx)
		fail(status, code, msg)
		detail := "endpoint=" + r.URL.Path + " code=" + code
		var upstream *engine.Error
		if errors.As(e, &upstream) {
			detail += fmt.Sprintf(" upstream_status=%d", upstream.Status)
		}
		_ = s.audit(context.WithoutCancel(r.Context()), r, domain.Admin{Username: "gateway"}, "engine.request_failed", en.ID, "failure", detail)
		slog.Warn("upstream request failed", "request_id", requestID, "engine_id", en.ID, "code", code)
		return
	}
	defer resp.Body.Close()
	if key.ID != "" {
		_ = s.Store.TouchAPIKey(r.Context(), key.ID)
	}
	if req.Stream {
		if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
			fail(502, "upstream_error", "Engine returned an invalid stream")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		beforeStream := time.Since(start)
		ttft, e := engine.Stream(ctx, w, resp.Body, m.Alias, func(u domain.Usage) { rec.Usage = u })
		if ttft > 0 {
			rec.TTFTMS = float64((beforeStream + ttft).Microseconds()) / 1000
		}
		if e != nil {
			_, code, _ := upstreamFailure(e, ctx)
			rec.ErrorCode = code
			if !w.wrote {
				fail(502, code, "Upstream stream failed")
			}
		}
		return
	}
	body, e := io.ReadAll(resp.Body)
	if e != nil {
		status, code, msg := upstreamFailure(e, ctx)
		fail(status, code, msg)
		return
	}
	normalized, usage, e := engine.NormalizeResponse(body, m.Alias)
	if e != nil {
		fail(502, "upstream_error", "Engine returned an invalid response")
		return
	}
	rec.Usage = usage
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(normalized)
}
func createdUnix(s string) int64 {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		return 0
	}
	return t.Unix()
}
func upstreamFailure(e error, ctx context.Context) (int, string, string) {
	var ne net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(e, &ne) && ne.Timeout() {
		return 504, "timeout", "Engine request timed out"
	}
	var ee *engine.Error
	if errors.As(e, &ee) {
		if ee.Code == "unsupported_endpoint" || ee.Status == 404 || ee.Status == 405 || ee.Status == 501 {
			return 501, "unsupported_endpoint", "Engine does not support this endpoint"
		}
		return 502, "upstream_error", "Engine returned an error"
	}
	return 503, "engine_unavailable", "Could not connect to engine"
}
