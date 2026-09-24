package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/domain"
	"llmgw/internal/safeguard"
)

func applySafeguardReference(raw json.RawMessage, target **string) error {
	if len(raw) == 0 {
		return nil
	}
	var id *string
	if err := json.Unmarshal(raw, &id); err != nil {
		return err
	}
	if id != nil && (strings.TrimSpace(*id) == "" || len(*id) > 200) {
		return errors.New("invalid safeguard ID")
	}
	*target = id
	return nil
}

func (s *Server) adminSafeguards(w http.ResponseWriter, r *http.Request, a domain.Admin, id, action string) {
	if action != "" {
		if action != "check" || id == "" {
			apiError(w, 404, "not_found", "Unknown action")
			return
		}
		if r.Method != http.MethodPost {
			methodError(w)
			return
		}
		bindings, err := s.Store.LoadSafeguards(r.Context(), []string{id})
		if err != nil {
			adminError(w, err)
			return
		}
		settings, err := s.Store.Settings(r.Context())
		if err != nil {
			adminError(w, err)
			return
		}
		binding := bindings[id]
		// A disabled profile can still be tested before it is enabled for clients.
		binding.Safeguard.Enabled = true
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(settings.RequestTimeoutSeconds)*time.Second)
		defer cancel()
		input, inErr := s.evaluateGuard(ctx, binding, settings, "input", "Hello.", "")
		output, outErr := s.evaluateGuard(ctx, binding, settings, "output", "Hello.", "Hello! How can I help?")
		lastError := ""
		if inErr != nil {
			lastError = "input: " + input.ErrorCode
		}
		if outErr != nil {
			if lastError != "" {
				lastError += "; "
			}
			lastError += "output: " + output.ErrorCode
		}
		saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer saveCancel()
		if err = s.Store.UpdateSafeguardCheck(saveCtx, id, time.Now().UTC().Format(time.RFC3339Nano), lastError); err != nil {
			adminError(w, err)
			return
		}
		result := "success"
		if lastError != "" {
			result = "failure"
		}
		if err = s.audit(saveCtx, r, a, "safeguard.checked", id, result, lastError); err != nil {
			adminError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": lastError == "", "input": input, "output": output})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if id != "" {
			g, err := s.Store.GetSafeguard(r.Context(), id)
			if err != nil {
				adminError(w, err)
				return
			}
			writeJSON(w, 200, g)
			return
		}
		items, err := s.Store.ListSafeguards(r.Context())
		if err != nil {
			adminError(w, err)
			return
		}
		collection(w, items, len(items))
	case http.MethodPost, http.MethodPut:
		var g domain.Safeguard
		if decode(r, &g) != nil || strings.TrimSpace(g.Name) == "" || len(g.Name) > 200 || g.Adapter != "qwen3guard_gen" || g.EngineID == "" || g.UpstreamModelID == "" {
			apiError(w, 400, "invalid_request", "A name, synchronized upstream model and supported safeguard adapter are required")
			return
		}
		verb, status := "safeguard.created", http.StatusCreated
		if r.Method == http.MethodPut {
			if id == "" {
				apiError(w, 400, "invalid_request", "Safeguard ID required")
				return
			}
			if _, err := s.Store.GetSafeguard(r.Context(), id); err != nil {
				adminError(w, err)
				return
			}
			g.ID = id
			verb = "safeguard.changed"
			status = http.StatusOK
		} else {
			if id != "" {
				apiError(w, 400, "invalid_request", "Create safeguards at the collection endpoint")
				return
			}
			g.ID = cryptoutil.RandomID()
		}
		if err := s.Store.SaveSafeguard(r.Context(), &g); err != nil {
			adminError(w, err)
			return
		}
		s.auditOK(r, a, verb, g.ID)
		writeJSON(w, status, g)
	case http.MethodDelete:
		if id == "" {
			apiError(w, 400, "invalid_request", "Safeguard ID required")
			return
		}
		if err := s.Store.DeleteSafeguard(r.Context(), id); err != nil {
			adminError(w, err)
			return
		}
		s.auditOK(r, a, "safeguard.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}

func guardFailure(err error) (int, string, string) {
	var ge *safeguard.Error
	if errors.As(err, &ge) {
		return ge.Status, ge.Code, ge.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 504, "guard_timeout", "Safeguard evaluation timed out"
	}
	return 503, "guard_unavailable", "Safeguard evaluation is unavailable"
}

func guardCheck(binding domain.SafeguardBinding, stage string) domain.GuardCheck {
	return domain.GuardCheck{Stage: stage, SafeguardID: binding.Safeguard.ID, SafeguardName: binding.Safeguard.Name, EngineID: binding.Engine.ID, EngineName: binding.Engine.Name, UpstreamModel: binding.Safeguard.UpstreamModelID, Result: "error"}
}

func (s *Server) evaluateGuard(ctx context.Context, binding domain.SafeguardBinding, settings domain.Settings, stage, input, output string) (check domain.GuardCheck, err error) {
	check = guardCheck(binding, stage)
	started := time.Now()
	defer func() {
		check.DurationMS = float64(time.Since(started).Microseconds()) / 1000
		if err != nil {
			_, check.ErrorCode, _ = guardFailure(err)
		}
	}()
	if int64(len(input))+int64(len(output)) > settings.GuardMaxTextBytes {
		return check, &safeguard.Error{Status: 503, Code: "guard_limit_exceeded", Message: "Safeguard inspection text is too large"}
	}
	secret := ""
	if len(binding.Engine.SecretCipher) != 0 {
		plain, decryptErr := s.Vault.Decrypt(binding.Engine.SecretCipher, "engine:"+binding.Engine.ID)
		if decryptErr != nil {
			return check, &safeguard.Error{Status: 503, Code: "guard_unavailable", Message: "Safeguard credentials are unavailable"}
		}
		secret = string(plain)
		clear(plain)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(settings.GuardTimeoutSeconds)*time.Second)
	defer cancel()
	v, err := safeguard.Evaluate(ctx, s.Client, binding, secret, stage, input, output)
	check.Label, check.Categories, check.Refusal, check.Usage = v.Label, v.Categories, v.Refusal, v.Usage
	if err == nil {
		check.Result = "checked"
	}
	return check, err
}

func (s *Server) enforceGuard(ctx context.Context, binding domain.SafeguardBinding, settings domain.Settings, stage, input, output string, blockControversial bool, rec *domain.AccessRecord) error {
	check, err := s.evaluateGuard(ctx, binding, settings, stage, input, output)
	if err == nil {
		check.Result = "allowed"
		if check.Label == "Unsafe" || blockControversial && check.Label == "Controversial" {
			check.Result, check.ErrorCode = "rejected", "guard_rejected"
			err = &safeguard.Error{Status: 403, Code: "guard_rejected", Message: "Content was rejected by the " + stage + " safeguard"}
		}
	}
	rec.GuardChecks = append(rec.GuardChecks, check)
	return err
}

func guardStageFailure(rec *domain.AccessRecord, binding domain.SafeguardBinding, stage string, err error) {
	check := guardCheck(binding, stage)
	_, check.ErrorCode, _ = guardFailure(err)
	rec.GuardChecks = append(rec.GuardChecks, check)
}

func (s *Server) guardDataDir() string {
	if s.Backups != nil {
		return s.Backups.DataDir
	}
	return filepath.Dir(s.Store.Path)
}
