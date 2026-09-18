package gateway

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"llmgw/internal/acl"
	"llmgw/internal/config"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/domain"
)

func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request, a domain.Admin) {
	if r.Method == "GET" {
		v, e := s.Store.Settings(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if r.Method != "PUT" {
		methodError(w)
		return
	}
	var v domain.Settings
	if decode(r, &v) != nil {
		apiError(w, 400, "invalid_request", "Invalid settings JSON")
		return
	}
	if e := config.Validate(v); e != nil {
		apiError(w, 400, "invalid_request", e.Error())
		return
	}
	if s.ApplySettings != nil {
		if e := s.ApplySettings(r.Context(), v); e != nil {
			apiError(w, 409, "settings_rejected", "Could not apply settings; verify the listen address is available")
			return
		}
	} else {
		if e := s.Store.SaveSettings(r.Context(), v); e != nil {
			adminError(w, e)
			return
		}
		if s.Logs != nil {
			if e := s.Logs.UpdateSettings(v); e != nil {
				adminError(w, e)
				return
			}
		}
	}
	s.auditOK(r, a, "settings.changed", "")
	writeJSON(w, 200, v)
}
func (s *Server) adminBackups(w http.ResponseWriter, r *http.Request, a domain.Admin, id, action string) {
	if s.Backups == nil {
		apiError(w, 503, "unavailable", "Backup manager is unavailable")
		return
	}
	if id == "import" {
		if r.Method != "POST" {
			methodError(w)
			return
		}
		passphrase := r.Header.Get("X-Backup-Passphrase")
		if r.Header.Get("X-Backup-Passphrase-Encoding") == "uri" {
			var err error
			passphrase, err = url.PathUnescape(passphrase)
			if err != nil {
				apiError(w, 400, "invalid_request", "Invalid passphrase encoding")
				return
			}
		}
		if e := s.Backups.StageUploadWithAudit(r.Context(), r.Body, passphrase, restoreAudit(r, a, "upload")); e != nil {
			apiError(w, 400, "invalid_backup", "Backup validation or decryption failed")
			return
		}
		s.auditOK(r, a, "backup.restored", "upload")
		writeJSON(w, 200, map[string]bool{"restart_required": true})
		return
	}
	if action == "download" {
		if r.Method != "GET" {
			methodError(w)
			return
		}
		path, e := s.Backups.Path(r.Context(), id)
		if e != nil {
			apiError(w, 404, "not_found", "Backup not found")
			return
		}
		f, e := os.Open(path)
		if e != nil {
			adminError(w, e)
			return
		}
		defer f.Close()
		if e = s.audit(r.Context(), r, a, "backup.downloaded", id, "success", ""); e != nil {
			adminError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
		_, _ = io.Copy(w, f)
		return
	}
	if action == "restore" {
		if r.Method != "POST" {
			methodError(w)
			return
		}
		var v struct {
			Passphrase string `json:"passphrase"`
		}
		if decode(r, &v) != nil {
			apiError(w, 400, "invalid_request", "Invalid JSON")
			return
		}
		if e := s.Backups.StageRestoreWithAudit(r.Context(), id, v.Passphrase, restoreAudit(r, a, id)); e != nil {
			apiError(w, 400, "invalid_backup", "Backup validation or decryption failed")
			return
		}
		s.auditOK(r, a, "backup.restored", id)
		writeJSON(w, 200, map[string]bool{"restart_required": true})
		return
	}
	if action != "" {
		apiError(w, 404, "not_found", "Not found")
		return
	}
	switch r.Method {
	case "GET":
		items, e := s.Backups.List(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		collection(w, items, len(items))
	case "POST":
		var v struct {
			Kind       string `json:"kind"`
			Passphrase string `json:"passphrase"`
		}
		if decode(r, &v) != nil || v.Kind != "local" && v.Kind != "portable" || v.Kind == "portable" && len(v.Passphrase) < 12 {
			apiError(w, 400, "invalid_request", "Choose local/portable; portable requires at least 12 passphrase characters")
			return
		}
		b, e := s.Backups.Create(r.Context(), v.Kind, v.Passphrase)
		if e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "backup.created", b.ID)
		writeJSON(w, 201, b)
	case "DELETE":
		if id == "" {
			apiError(w, 400, "invalid_request", "Backup ID required")
			return
		}
		if e := s.Backups.Delete(r.Context(), id); e != nil {
			adminError(w, e)
			return
		}
		s.auditOK(r, a, "backup.deleted", id)
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		methodError(w)
	}
}
func restoreAudit(r *http.Request, a domain.Admin, target string) domain.Audit {
	return domain.Audit{ID: cryptoutil.RandomID(), Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ActorID: a.ID, ActorName: a.Username, SourceIP: acl.SourceIP(r.RemoteAddr).String(), Action: "backup.restored", Target: target, Result: "success"}
}
