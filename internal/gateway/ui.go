package gateway

import (
	"io/fs"
	"net/http"
	"strings"

	"llmgw/web"
)

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		methodError(w)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/static/") {
		files, e := fs.Sub(web.Assets, "static")
		if e != nil {
			apiError(w, 500, "internal_error", "UI unavailable")
			return
		}
		http.StripPrefix("/admin/static/", http.FileServer(http.FS(files))).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/setup" {
		if !localSetup(r) {
			apiError(w, 403, "forbidden", "Initial setup requires localhost")
			return
		}
		a, e := s.Store.ListAdmins(r.Context())
		if e != nil {
			adminError(w, e)
			return
		}
		if len(a) > 0 {
			apiError(w, 404, "not_found", "Setup is disabled")
			return
		}
	}
	data, e := web.Assets.ReadFile("static/index.html")
	if e != nil {
		apiError(w, 500, "internal_error", "UI unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
