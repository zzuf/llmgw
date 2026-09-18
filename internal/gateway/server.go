// Package gateway serves the public protocols and the administrator API on one listener.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"llmgw/internal/acl"
	"llmgw/internal/auth"
	"llmgw/internal/backup"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/engine"
	"llmgw/internal/logging"
)

type Server struct {
	Store         *database.Store
	Vault         *cryptoutil.Vault
	Logs          *logging.Logger
	Backups       *backup.Manager
	Client        *http.Client
	ApplySettings func(context.Context, domain.Settings) error
	healthMu      sync.Mutex
}

func New(store *database.Store, vault *cryptoutil.Vault, logs *logging.Logger, backups *backup.Manager) *Server {
	return &Server{Store: store, Vault: vault, Logs: logs, Backups: backups, Client: engine.NewHTTPClient()}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *responseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(200)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := &responseWriter{ResponseWriter: w, status: 200}
	id := cryptoutil.RandomID()
	rw.Header().Set("X-Request-ID", id)
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Referrer-Policy", "same-origin")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	defer func() {
		if recover() != nil {
			slog.Error("request panic recovered", "request_id", id)
			if !rw.wrote {
				apiError(rw, 500, "internal_error", "Internal server error")
			}
		}
	}()
	switch {
	case r.URL.Path == "/health":
		if r.Method != "GET" {
			methodError(rw)
			return
		}
		writeJSON(rw, 200, map[string]string{"status": "ok"})
	case strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/v1":
		s.public(rw, r, id)
	case strings.HasPrefix(r.URL.Path, "/admin/api/"):
		rw.Header().Set("Cache-Control", "no-store")
		s.admin(rw, r)
	case r.URL.Path == "/setup" || r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/"):
		s.ui(rw, r)
	case r.URL.Path == "/":
		http.Redirect(rw, r, "/admin/", http.StatusSeeOther)
	default:
		apiError(rw, 404, "not_found", "Not found")
	}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": message, "type": "gateway_error", "code": code}})
}
func methodError(w http.ResponseWriter) { apiError(w, 405, "method_not_allowed", "Method not allowed") }
func decode(r *http.Request, dest any) error {
	d := json.NewDecoder(r.Body)
	if e := d.Decode(dest); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
func (s *Server) audit(ctx context.Context, r *http.Request, a domain.Admin, action, target, result, detail string) error {
	return s.Store.AddAudit(ctx, domain.Audit{ID: cryptoutil.RandomID(), Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ActorID: a.ID, ActorName: a.Username, SourceIP: acl.SourceIP(r.RemoteAddr).String(), Action: action, Target: target, Result: result, Detail: detail})
}
func (s *Server) auditOK(r *http.Request, a domain.Admin, action, target string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if e := s.audit(ctx, r, a, action, target, "success", ""); e != nil {
		slog.Error("audit write failed", "action", action)
	}
}
func (s *Server) session(r *http.Request) (domain.Admin, domain.Session, error) {
	return (&auth.Manager{Store: s.Store}).Authenticate(r.Context(), r)
}
