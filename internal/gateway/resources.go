package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/domain"
	"llmgw/internal/engine"
)

func (s *Server) adminEngines(w http.ResponseWriter, r *http.Request, a domain.Admin, id, action string) {
	if action != "" {
		if r.Method != "POST" {
			methodError(w)
			return
		}
		if action != "check" && action != "sync" {
			apiError(w, 404, "not_found", "Unknown action")
			return
		}
		en, e := s.CheckEngine(r.Context(), id)
		if e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "engine."+action, id)
		writeJSON(w, 200, en)
		return
	}
	switch r.Method {
	case "GET":
		v, e := s.Store.ListEngines(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, v, len(v))
	case "POST", "PUT":
		var v struct {
			domain.Engine
			Secret      string `json:"secret"`
			ClearSecret bool   `json:"clear_secret"`
		}
		if decode(r, &v) != nil {
			apiError(w, 400, "invalid_request", "Invalid engine JSON")
			return
		}
		v.Name = strings.TrimSpace(v.Name)
		if v.Name == "" || len(v.Name) > 200 || engine.ValidateBaseURL(v.BaseURL) != nil {
			apiError(w, 400, "invalid_request", "Name and an HTTP(S) API base URL without credentials/query/fragment are required")
			return
		}
		if !slices.Contains([]string{"auto", "generic", "lmstudio", "omlx", "mlxserve"}, v.Type) || !slices.Contains([]string{"none", "bearer", "x-api-key"}, v.AuthType) {
			apiError(w, 400, "invalid_request", "Invalid engine or authentication type")
			return
		}
		en := v.Engine
		verb := "engine.created"
		status := 201
		if r.Method == "PUT" {
			old, e := s.Store.GetEngine(r.Context(), id)
			if e != nil {
				adminError(w, e)
				return
			}
			en.ID = id
			en.CreatedAt = old.CreatedAt
			en.SecretCipher = old.SecretCipher
			en.Status = old.Status
			en.LastCheck = old.LastCheck
			en.LastSuccess = old.LastSuccess
			en.LastError = old.LastError
			en.LatencyMS = old.LatencyMS
			en.DetectedType = old.DetectedType
			verb = "engine.changed"
			status = 200
		} else {
			en.ID = cryptoutil.RandomID()
			en.Status = "Offline"
			en.DetectedType = ""
			en.LastCheck = ""
			en.LastSuccess = ""
			en.LastError = ""
			en.CreatedAt = ""
			en.UpdatedAt = ""
			en.LatencyMS = 0
		}
		if v.ClearSecret || en.AuthType == "none" {
			en.SecretCipher = nil
		}
		if v.Secret != "" {
			cipher, e := s.Vault.Encrypt([]byte(v.Secret), "engine:"+en.ID)
			if e != nil {
				adminError(w, e)
				return
			}
			en.SecretCipher = cipher
		}
		if en.AuthType != "none" && len(en.SecretCipher) == 0 {
			apiError(w, 400, "invalid_request", "Engine authentication requires a secret")
			return
		}
		if e := s.Store.SaveEngine(r.Context(), &en); e != nil {
			adminError(w, e)
			return
		}
		en.HasSecret = len(en.SecretCipher) > 0
		s.auditOK(r, a, verb, en.ID)
		writeJSON(w, status, en)
	case "DELETE":
		if id == "" {
			apiError(w, 400, "invalid_request", "Engine ID required")
			return
		}
		if e := s.Store.DeleteEngine(r.Context(), id); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "engine.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}

// CheckEngine discovers only after a successful models response. Failed probes retain availability.
func (s *Server) CheckEngine(ctx context.Context, id string) (domain.Engine, error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	en, e := s.Store.GetEngine(ctx, id)
	if e != nil {
		return en, e
	}
	if !en.Enabled {
		return en, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	secret := ""
	if len(en.SecretCipher) > 0 {
		plain, e := s.Vault.Decrypt(en.SecretCipher, "engine:"+en.ID)
		if e != nil {
			_ = s.Store.UpdateHealth(ctx, id, "Degraded", "Cannot decrypt engine credentials", 0, en.DetectedType)
			return s.Store.GetEngine(ctx, id)
		}
		secret = string(plain)
	}
	started := time.Now()
	items, detected, probeErr := engine.New(en.Type).ListModels(ctx, s.Client, en, secret)
	latency := float64(time.Since(started).Microseconds()) / 1000
	status := "Online"
	message := ""
	if probeErr != nil {
		status = "Offline"
		message = "Engine connection failed or timed out"
		var ee *engine.Error
		if errors.As(probeErr, &ee) {
			status = "Degraded"
			message = fmt.Sprintf("%s (HTTP %d)", ee.Message, ee.Status)
		}
	}
	// The request context may have timed out; persist the result with an independent short deadline.
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer saveCancel()
	if e = s.Store.UpdateHealth(saveCtx, id, status, message, latency, detected); e != nil {
		return en, e
	}
	if probeErr == nil {
		if e = s.Store.SyncModels(saveCtx, id, items); e != nil {
			return en, e
		}
	}
	return s.Store.GetEngine(saveCtx, id)
}
func (s *Server) adminModels(w http.ResponseWriter, r *http.Request, a domain.Admin, id string) {
	switch r.Method {
	case "GET":
		v, e := s.Store.ListModels(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, v, len(v))
	case "POST", "PUT":
		var m domain.Model
		if decode(r, &m) != nil {
			apiError(w, 400, "invalid_request", "Invalid model JSON")
			return
		}
		m.Alias = strings.TrimSpace(m.Alias)
		if m.Alias == "" || len(m.Alias) > 200 || strings.ContainsAny(m.Alias, " \t\r\n\x00") {
			apiError(w, 400, "invalid_request", "Alias must be a nonempty identifier without whitespace")
			return
		}
		validCaps := []string{"models", "responses", "chat_completions", "completions", "embeddings", "rerank", "messages", "vision", "tools", "streaming"}
		for c := range m.Capabilities {
			if !slices.Contains(validCaps, c) {
				apiError(w, 400, "invalid_request", "Unknown capability: "+c)
				return
			}
		}
		action := "model.created"
		status := 201
		var old domain.Model
		if r.Method == "PUT" {
			var e error
			old, e = s.Store.GetModel(r.Context(), id)
			if e != nil {
				adminError(w, e)
				return
			}
			m.ID = id
			m.CreatedAt = old.CreatedAt
			action = "model.changed"
			status = 200
		} else {
			m.ID = cryptoutil.RandomID()
			m.CreatedAt = ""
			m.UpdatedAt = ""
		}
		if e := s.Store.SaveModel(r.Context(), &m); e != nil {
			if strings.Contains(e.Error(), "invalid") || strings.Contains(e.Error(), "CIDR") {
				apiError(w, 400, "invalid_request", "Invalid model fields or IP/CIDR")
				return
			}
			adminError(w, e)
			return
		}
		s.auditOK(r, a, action, m.ID)
		if r.Method == "PUT" {
			if old.Alias != m.Alias {
				s.auditOK(r, a, "model.alias_changed", m.ID)
			}
			if old.Published != m.Published {
				verb := "model.hidden"
				if m.Published {
					verb = "model.published"
				}
				s.auditOK(r, a, verb, m.ID)
			}
			if !reflect.DeepEqual(old.AllowedIPs, m.AllowedIPs) || !reflect.DeepEqual(old.AllowedAPIKeys, m.AllowedAPIKeys) {
				s.auditOK(r, a, "model.acl_changed", m.ID)
			}
		}
		writeJSON(w, status, m)
	case "DELETE":
		if id == "" {
			apiError(w, 400, "invalid_request", "Model ID required")
			return
		}
		if e := s.Store.DeleteModel(r.Context(), id); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "model.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}
func (s *Server) adminKeys(w http.ResponseWriter, r *http.Request, a domain.Admin, id, action string) {
	if action != "" {
		if action != "reveal" {
			apiError(w, 404, "not_found", "Unknown action")
			return
		}
		if r.Method != "POST" {
			methodError(w)
			return
		}
		k, e := s.Store.GetAPIKey(r.Context(), id)
		if e != nil {
			adminError(w, e)
			return
		}
		secret, e := s.Vault.Decrypt(k.SecretCipher, "api-key:"+id)
		if e != nil {
			adminError(w, e)
			return
		}
		if e = s.audit(r.Context(), r, a, "api_key.secret_viewed", id, "success", ""); e != nil {
			adminError(w, e)
			return
		}
		writeJSON(w, 200, map[string]string{"secret": string(secret)})
		return
	}
	switch r.Method {
	case "GET":
		items, e := s.Store.ListAPIKeys(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, items, len(items))
	case "POST", "PUT":
		var v struct {
			Name    string   `json:"name"`
			Tags    []string `json:"tags"`
			Enabled bool     `json:"enabled"`
		}
		if decode(r, &v) != nil || strings.TrimSpace(v.Name) == "" || len(v.Name) > 200 || len(v.Tags) > 50 {
			apiError(w, 400, "invalid_request", "Invalid API key name or tags")
			return
		}
		for _, tag := range v.Tags {
			if len(tag) > 100 {
				apiError(w, 400, "invalid_request", "Tag is too long")
				return
			}
		}
		k := domain.APIKey{Name: v.Name, Tags: v.Tags, Enabled: v.Enabled}
		action := "api_key.created"
		status := 201
		if r.Method == "PUT" {
			old, e := s.Store.GetAPIKey(r.Context(), id)
			if e != nil {
				adminError(w, e)
				return
			}
			k.ID = id
			k.SecretCipher = old.SecretCipher
			k.SecretHash = old.SecretHash
			k.Suffix = old.Suffix
			k.CreatedAt = old.CreatedAt
			k.LastUsedAt = old.LastUsedAt
			action = "api_key.changed"
			if old.Enabled && !k.Enabled {
				action = "api_key.disabled"
			}
			status = 200
		} else {
			k.ID = cryptoutil.RandomID()
			secret, e := cryptoutil.GenerateAPIKey()
			if e != nil {
				adminError(w, e)
				return
			}
			k.SecretHash = cryptoutil.HashSecret(secret)
			k.Suffix = secret[len(secret)-4:]
			k.SecretCipher, e = s.Vault.Encrypt([]byte(secret), "api-key:"+k.ID)
			if e != nil {
				adminError(w, e)
				return
			}
		}
		if e := s.Store.SaveAPIKey(r.Context(), &k); e != nil {
			adminError(w, e)
			return
		}
		k.Masked = "llmgw_****************" + k.Suffix
		s.auditOK(r, a, action, k.ID)
		writeJSON(w, status, k)
	case "DELETE":
		if id == "" {
			apiError(w, 400, "invalid_request", "API key ID required")
			return
		}
		if e := s.Store.DeleteAPIKey(r.Context(), id); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "api_key.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}
