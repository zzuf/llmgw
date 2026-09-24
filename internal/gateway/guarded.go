package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"llmgw/internal/domain"
	"llmgw/internal/engine"
	"llmgw/internal/safeguard"
)

type guardPolicy struct {
	input, output      *domain.SafeguardBinding
	settings           domain.Settings
	text               string
	blockControversial bool
}

func (s *Server) prepareGuards(ctx context.Context, req *engine.Request, key domain.APIKey, settings domain.Settings, rec *domain.AccessRecord) (*guardPolicy, error) {
	if key.ID == "" || key.InputSafeguardID == nil && key.OutputSafeguardID == nil {
		return nil, nil
	}
	ids := []string{}
	for _, id := range []*string{key.InputSafeguardID, key.OutputSafeguardID} {
		if id != nil {
			ids = append(ids, *id)
		}
	}
	bindings, err := s.Store.LoadSafeguards(ctx, ids)
	if err != nil {
		return nil, &safeguard.Error{Status: 503, Code: "guard_unavailable", Message: "Safeguard configuration is unavailable"}
	}
	policy := &guardPolicy{settings: settings, blockControversial: key.BlockControversial}
	if key.InputSafeguardID != nil {
		v := bindings[*key.InputSafeguardID]
		policy.input = &v
	}
	if key.OutputSafeguardID != nil {
		v := bindings[*key.OutputSafeguardID]
		policy.output = &v
	}
	for _, check := range []struct {
		stage   string
		binding *domain.SafeguardBinding
	}{{"input", policy.input}, {"output", policy.output}} {
		if check.binding == nil {
			continue
		}
		b := check.binding
		if !b.Safeguard.Enabled || !b.Safeguard.Available || !b.Engine.Enabled {
			err = &safeguard.Error{Status: 503, Code: "guard_unavailable", Message: "Configured safeguard is disabled or unavailable"}
			guardStageFailure(rec, *b, check.stage, err)
			return nil, err
		}
	}
	// Output moderation also needs the complete original input context.
	policy.text, err = safeguard.Input(req, settings.GuardMaxTextBytes)
	if err != nil {
		stage, binding := "input", policy.input
		if binding == nil {
			stage, binding = "output", policy.output
		}
		guardStageFailure(rec, *binding, stage, err)
		return nil, err
	}
	_ = s.Store.TouchAPIKey(ctx, key.ID)
	if policy.input != nil {
		if err = s.enforceGuard(ctx, *policy.input, settings, "input", policy.text, "", policy.blockControversial, rec); err != nil {
			return nil, err
		}
	}
	return policy, nil
}

func (s *Server) inspectOutput(ctx context.Context, policy *guardPolicy, text string, applicable bool, rec *domain.AccessRecord) error {
	if !applicable {
		check := guardCheck(*policy.output, "output")
		check.Result = "not_applicable"
		rec.GuardChecks = append(rec.GuardChecks, check)
		return nil
	}
	return s.enforceGuard(ctx, *policy.output, policy.settings, "output", policy.text, text, policy.blockControversial, rec)
}

// forwardGuarded commits no downstream headers or body until the complete output
// has been validated and accepted. Streaming is ingested to an unlinked file.
func (s *Server) forwardGuarded(ctx context.Context, w *responseWriter, resp *http.Response, req *engine.Request, alias string, policy *guardPolicy, rec *domain.AccessRecord, start, upstreamStart time.Time) error {
	if req.Stream {
		if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
			return &engine.Error{Code: "upstream_error", Status: 502, Message: "Engine returned an invalid stream"}
		}
		beforeCapture := time.Since(upstreamStart)
		captured, err := safeguard.CaptureStream(ctx, resp.Body, req.Endpoint, alias, s.guardDataDir(), policy.settings.GuardMaxTextBytes, policy.settings.GuardMaxSpoolBytes)
		if err != nil {
			guardStageFailure(rec, *policy.output, "output", err)
			return err
		}
		defer captured.Close()
		rec.Usage = captured.Usage
		if captured.UpstreamTTFT > 0 {
			rec.UpstreamTTFTMS = float64((beforeCapture + captured.UpstreamTTFT).Microseconds()) / 1000
		}
		if err = s.inspectOutput(ctx, policy, captured.Text, captured.Applicable, rec); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		beforeReplay := time.Since(start)
		ttft, err := captured.Replay(ctx, w)
		if ttft > 0 {
			rec.TTFTMS = float64((beforeReplay + ttft).Microseconds()) / 1000
		}
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, policy.settings.GuardMaxSpoolBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > policy.settings.GuardMaxSpoolBytes {
		err = &safeguard.Error{Status: 503, Code: "guard_limit_exceeded", Message: "Safeguard response buffering limit exceeded"}
		guardStageFailure(rec, *policy.output, "output", err)
		return err
	}
	normalized, usage, err := engine.NormalizeResponse(body, alias)
	if err != nil {
		return err
	}
	rec.Usage = usage
	text, applicable, err := safeguard.Output(req.Endpoint, normalized, policy.settings.GuardMaxTextBytes)
	if err != nil {
		guardStageFailure(rec, *policy.output, "output", err)
		return err
	}
	if err = s.inspectOutput(ctx, policy, text, applicable, rec); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(normalized)
	return err
}
