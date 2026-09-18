package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"llmgw/internal/acl"
	"llmgw/internal/auth"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/logging"
)

// Bound Argon2 working memory independently of inference concurrency.
var passwordWork = make(chan struct{}, 2)

func acquirePasswordWork(w http.ResponseWriter) bool {
	select {
	case passwordWork <- struct{}{}:
		return true
	default:
		apiError(w, 429, "busy", "Password verification is busy; retry shortly")
		return false
	}
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/"), "/")
	if path == "csrf" {
		if r.Method != "GET" {
			methodError(w)
			return
		}
		if !auth.SameOrigin(r) {
			apiError(w, 403, "forbidden", "Cross-origin request rejected")
			return
		}
		writeJSON(w, 200, map[string]string{"csrf_token": auth.PreauthCSRF(w, r)})
		return
	}
	if path == "login" || path == "setup" {
		s.login(w, r, path == "setup")
		return
	}
	if !auth.SameOrigin(r) {
		apiError(w, 403, "forbidden", "Cross-origin request rejected")
		return
	}
	a, session, e := s.session(r)
	if e != nil {
		apiError(w, 401, "unauthorized", "Administrator login required")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && !auth.CSRF(r, session.CSRFToken) {
		apiError(w, 403, "forbidden", "Invalid CSRF token or origin")
		return
	}
	parts := strings.Split(path, "/")
	resource := parts[0]
	id := ""
	action := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	if len(parts) > 2 {
		action = parts[2]
	}
	if len(parts) > 3 {
		apiError(w, 404, "not_found", "Not found")
		return
	}
	switch resource {
	case "session":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		writeJSON(w, 200, map[string]any{"admin": a, "csrf_token": session.CSRFToken})
	case "logout":
		if r.Method != "POST" {
			methodError(w)
			return
		}
		if e := (&auth.Manager{Store: s.Store}).Logout(r.Context(), w, r); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "admin.logout", a.ID)
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "engines":
		s.adminEngines(w, r, a, id, action)
	case "upstream-models":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		items, e := s.Store.ListUpstreamModels(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, items, len(items))
	case "models":
		s.adminModels(w, r, a, id)
	case "keys":
		s.adminKeys(w, r, a, id, action)
	case "admins":
		s.adminUsers(w, r, a, id)
	case "dashboard":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		if s.Logs != nil {
			_ = s.Logs.Flush(r.Context())
		}
		v, e := logging.Dashboard(r.Context(), s.Store.DB)
		if e != nil {
			adminError(w, e)
			return
		}
		writeJSON(w, 200, v)
	case "statistics":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		group := r.URL.Query().Get("group")
		if group == "" {
			group = "day"
		}
		v, e := logging.Statistics(r.Context(), s.Store.DB, group, queryInt(r, "days", 30, 1, 36500))
		if e != nil {
			apiError(w, 400, "invalid_request", "Invalid statistics query")
			return
		}
		collection(w, v, len(v))
	case "access-logs":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		v, n, e := logging.AccessLogs(r.Context(), s.Store.DB, r.URL.Query().Get("q"), queryInt(r, "page", 1, 1, 100000), queryInt(r, "page_size", 25, 1, 100))
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, v, n)
	case "audit-logs":
		if r.Method != "GET" {
			methodError(w)
			return
		}
		v, n, e := logging.AuditLogs(r.Context(), s.Store.DB, r.URL.Query().Get("q"), queryInt(r, "page", 1, 1, 100000), queryInt(r, "page_size", 25, 1, 100))
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, v, n)
	case "settings":
		s.adminSettings(w, r, a)
	case "backups":
		s.adminBackups(w, r, a, id, action)
	default:
		apiError(w, 404, "not_found", "Not found")
	}
}
func collection(w http.ResponseWriter, items any, total int) {
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}
func queryInt(r *http.Request, key string, def, min, max int) int {
	v, e := strconv.Atoi(r.URL.Query().Get(key))
	if e != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
func adminError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, database.ErrNotFound):
		apiError(w, 404, "not_found", "Resource not found")
	case errors.Is(e, database.ErrConflict):
		apiError(w, 409, "conflict", "Value already exists or resource is still referenced")
	case errors.Is(e, database.ErrLastAdmin):
		apiError(w, 409, "conflict", "The last administrator cannot be deleted")
	case errors.Is(e, database.ErrAlreadySetup):
		apiError(w, 409, "already_setup", "Initial setup has already completed")
	default:
		apiError(w, 500, "internal_error", "Operation failed; inspect server diagnostics")
	}
}
func localSetup(r *http.Request) bool {
	if !acl.SourceIP(r.RemoteAddr).IsLoopback() {
		return false
	}
	host := r.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, e := netip.ParseAddr(strings.Trim(host, "[]"))
	return e == nil && ip.Unmap().IsLoopback()
}
func (s *Server) login(w http.ResponseWriter, r *http.Request, setup bool) {
	if r.Method != "POST" {
		methodError(w)
		return
	}
	if !auth.ValidPreauth(r) {
		apiError(w, 403, "forbidden", "Invalid CSRF token or origin")
		return
	}
	if setup && !localSetup(r) {
		apiError(w, 403, "forbidden", "Initial setup requires localhost")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decode(r, &input) != nil || !validUsername(input.Username) || len(input.Password) < 1 || len(input.Password) > 1024 {
		apiError(w, 400, "invalid_request", "Invalid username or password")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	var a domain.Admin
	if setup {
		if len(input.Password) < 12 {
			apiError(w, 400, "invalid_request", "Use a password of at least 12 characters")
			return
		}
		admins, e := s.Store.ListAdmins(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		if len(admins) > 0 {
			adminError(w, database.ErrAlreadySetup)
			return
		}
		hash, e := cryptoutil.HashPassword(input.Password)
		if e != nil {
			adminError(w, e)
			return
		}
		a = domain.Admin{ID: cryptoutil.RandomID(), Username: input.Username, PasswordHash: hash}
		if e = s.Store.CreateAdmin(r.Context(), &a, true); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "admin.created", a.ID)
	} else {
		var e error
		a, e = s.Store.AdminByUsername(r.Context(), input.Username)
		if e != nil { // Perform the same KDF work for missing accounts to reduce enumeration by timing.
			_, _ = cryptoutil.HashPassword(input.Password)
		}
		if e != nil || !cryptoutil.VerifyPassword(a.PasswordHash, input.Password) {
			_ = s.audit(r.Context(), r, domain.Admin{Username: input.Username}, "admin.login.failure", "", "failure", "")
			apiError(w, 401, "unauthorized", "Invalid username or password")
			return
		}
	}
	csrf, e := (&auth.Manager{Store: s.Store}).NewSession(r.Context(), w, r, a)
	if e != nil {
		adminError(w, e)
		return
	}
	s.auditOK(r, a, "admin.login.success", a.ID)
	writeJSON(w, 200, map[string]any{"admin": a, "csrf_token": csrf})
}
func validUsername(u string) bool {
	return len(strings.TrimSpace(u)) > 0 && len(u) <= 128 && !strings.ContainsAny(u, "\r\n\x00")
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, actor domain.Admin, id string) {
	switch r.Method {
	case "GET":
		items, e := s.Store.ListAdmins(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, items, len(items))
	case "POST", "PUT":
		if !acquirePasswordWork(w) {
			return
		}
		defer func() { <-passwordWork }()
		var v struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decode(r, &v) != nil || len(v.Password) < 12 || len(v.Password) > 1024 {
			apiError(w, 400, "invalid_request", "Use a password of 12–1024 characters")
			return
		}
		if r.Method == "POST" && !validUsername(v.Username) {
			apiError(w, 400, "invalid_request", "Invalid username")
			return
		}
		hash, e := cryptoutil.HashPassword(v.Password)
		if e != nil {
			adminError(w, e)
			return
		}
		if r.Method == "POST" {
			admins, e := s.Store.ListAdmins(r.Context())
			if e != nil {
				adminError(w, e)
				return
			}
			if len(admins) >= 30 {
				apiError(w, 409, "conflict", "Maximum 30 administrators")
				return
			}
			a := domain.Admin{ID: cryptoutil.RandomID(), Username: v.Username, PasswordHash: hash}
			if e = s.Store.CreateAdmin(r.Context(), &a, false); e != nil {
				adminError(w, e)
				return
			}
			s.auditOK(r, actor, "admin.created", a.ID)
			writeJSON(w, 201, a)
		} else {
			if id == "" {
				apiError(w, 400, "invalid_request", "Administrator ID required")
				return
			}
			if e = s.Store.ChangePassword(r.Context(), id, hash); e != nil {
				adminError(w, e)
				return
			}
			s.auditOK(r, actor, "admin.password_changed", id)
			writeJSON(w, 200, map[string]bool{"ok": true, "sessions_revoked": true})
		}
	case "DELETE":
		if id == "" {
			apiError(w, 400, "invalid_request", "Administrator ID required")
			return
		}
		if e := s.Store.DeleteAdmin(r.Context(), id); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, actor, "admin.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}
