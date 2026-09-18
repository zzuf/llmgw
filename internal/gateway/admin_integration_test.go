package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"llmgw/internal/auth"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

const administratorPassword = "correct-horse-battery-42"

type adminPrincipal struct {
	cookie *http.Cookie
	csrf   string
	admin  domain.Admin
}

func preauth(t *testing.T, f *gatewayFixture) (*http.Cookie, string) {
	t.Helper()
	w := serve(t, f.server, requestJSON(t, "GET", "/admin/api/csrf", nil), 200)
	result := decodeResponse[struct {
		Token string `json:"csrf_token"`
	}](t, w)
	if len(result.Token) < 32 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsafe preauth challenge: %s", w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "llmgw_pre_csrf" {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("unsafe preauth cookie: %+v", cookie)
			}
			return cookie, result.Token
		}
	}
	t.Fatal("missing preauthentication cookie")
	return nil, ""
}

func signIn(t *testing.T, f *gatewayFixture, setup bool, username, password string, old *http.Cookie) adminPrincipal {
	t.Helper()
	challenge, csrf := preauth(t, f)
	path := "/admin/api/login"
	if setup {
		path = "/admin/api/setup"
	}
	r := requestJSON(t, "POST", path, map[string]string{"username": username, "password": password})
	r.AddCookie(challenge)
	if old != nil {
		r.AddCookie(old)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "http://localhost:8080")
	w := serve(t, f.server, r, 200)
	result := decodeResponse[struct {
		Admin domain.Admin `json:"admin"`
		CSRF  string       `json:"csrf_token"`
	}](t, w)
	if result.Admin.ID == "" || result.Admin.Username != username || len(result.CSRF) < 32 {
		t.Fatalf("login result=%s", w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == auth.CookieName {
			if cookie.Path != "/admin" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 86400 {
				t.Fatalf("unsafe session cookie: %+v", cookie)
			}
			return adminPrincipal{cookie, result.CSRF, result.Admin}
		}
	}
	t.Fatal("login omitted session cookie")
	return adminPrincipal{}
}

func (a adminPrincipal) request(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	r := requestJSON(t, method, path, body)
	r.AddCookie(a.cookie)
	r.Header.Set("X-CSRF-Token", a.csrf)
	r.Header.Set("Origin", "http://localhost:8080")
	return r
}

func TestSetupRequiresLocalPeerAndPreauthCSRFThenDisables(t *testing.T) {
	f := newGatewayFixture(t)
	serve(t, f.server, requestJSON(t, "GET", "/setup", nil), 200)
	credentials := map[string]string{"username": "owner", "password": administratorPassword}
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/admin/api/setup", credentials), 403), "forbidden")
	challenge, csrf := preauth(t, f)
	for _, test := range []struct{ name, remote, host, origin, token string }{
		{"remote peer", "203.0.113.5:3333", "localhost:8080", "http://localhost:8080", csrf},
		{"DNS rebinding host", "127.0.0.1:3333", "evil.example", "http://evil.example", csrf},
		{"cross origin", "127.0.0.1:3333", "localhost:8080", "https://evil.example", csrf},
		{"wrong CSRF", "127.0.0.1:3333", "localhost:8080", "http://localhost:8080", "wrong"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := requestJSON(t, "POST", "/admin/api/setup", credentials)
			r.RemoteAddr = test.remote
			r.Host = test.host
			r.AddCookie(challenge)
			r.Header.Set("Origin", test.origin)
			r.Header.Set("X-CSRF-Token", test.token)
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			assertErrorCode(t, serve(t, f.server, r, 403), "forbidden")
		})
	}
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	serve(t, f.server, a.request(t, "GET", "/admin/api/session", nil), 200)
	serve(t, f.server, requestJSON(t, "GET", "/setup", nil), 404)
	r := requestJSON(t, "POST", "/admin/api/setup", credentials)
	r.AddCookie(challenge)
	r.Header.Set("X-CSRF-Token", csrf)
	assertErrorCode(t, serve(t, f.server, r, 409), "already_setup")
	admins, err := f.store.ListAdmins(context.Background())
	if err != nil || len(admins) != 1 {
		t.Fatalf("administrators=%+v err=%v", admins, err)
	}
}

func TestAdminSessionRotationPasswordRevocationAndCSRF(t *testing.T) {
	f := newGatewayFixture(t)
	first := signIn(t, f, true, "owner", administratorPassword, nil)
	second := signIn(t, f, false, "owner", administratorPassword, first.cookie)
	if first.cookie.Value == second.cookie.Value || first.csrf == second.csrf {
		t.Fatal("login reused an existing session or CSRF token")
	}
	assertErrorCode(t, serve(t, f.server, first.request(t, "GET", "/admin/api/session", nil), 401), "unauthorized")
	if _, err := f.store.GetSession(context.Background(), cryptoutil.HashSecret(first.cookie.Value)); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("old session still stored: %v", err)
	}
	for _, test := range []struct{ name, csrf, origin, fetchSite string }{
		{"missing token", "", "http://localhost:8080", ""},
		{"wrong token", "wrong", "http://localhost:8080", ""},
		{"cross origin", second.csrf, "https://evil.example", ""},
		{"cross site", second.csrf, "http://localhost:8080", "cross-site"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := second.request(t, "POST", "/admin/api/logout", nil)
			r.Header.Set("X-CSRF-Token", test.csrf)
			r.Header.Set("Origin", test.origin)
			r.Header.Set("Sec-Fetch-Site", test.fetchSite)
			assertErrorCode(t, serve(t, f.server, r, 403), "forbidden")
			serve(t, f.server, second.request(t, "GET", "/admin/api/session", nil), 200)
		})
	}
	third := signIn(t, f, false, "owner", administratorPassword, nil)
	newPassword := "new-administrator-password-64"
	serve(t, f.server, second.request(t, "PUT", "/admin/api/admins/"+second.admin.ID, map[string]string{"password": newPassword}), 200)
	for _, session := range []adminPrincipal{second, third} {
		assertErrorCode(t, serve(t, f.server, session.request(t, "GET", "/admin/api/session", nil), 401), "unauthorized")
	}
	challenge, csrf := preauth(t, f)
	wrong := requestJSON(t, "POST", "/admin/api/login", map[string]string{"username": "owner", "password": administratorPassword})
	wrong.AddCookie(challenge)
	wrong.Header.Set("X-CSRF-Token", csrf)
	assertErrorCode(t, serve(t, f.server, wrong, 401), "unauthorized")
	fourth := signIn(t, f, false, "owner", newPassword, nil)
	w := serve(t, f.server, fourth.request(t, "POST", "/admin/api/logout", nil), 200)
	assertErrorCode(t, serve(t, f.server, fourth.request(t, "GET", "/admin/api/session", nil), 401), "unauthorized")
	var cleared bool
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == auth.CookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear session cookie")
	}
}

func TestAdminSessionDoesNotExposeCSRFToCrossOriginRequests(t *testing.T) {
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	r := a.request(t, "GET", "/admin/api/session", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := serve(t, f.server, r, 403)
	if strings.Contains(w.Body.String(), a.csrf) {
		t.Fatal("cross-origin response exposed session CSRF token")
	}
}

func TestConcurrentSetupCreatesExactlyOneAdministrator(t *testing.T) {
	f := newGatewayFixture(t)
	challenge, csrf := preauth(t, f)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var workers sync.WaitGroup
	for _, username := range []string{"first", "second"} {
		r := requestJSON(t, "POST", "/admin/api/setup", map[string]string{"username": username, "password": administratorPassword})
		r.AddCookie(challenge)
		r.Header.Set("X-CSRF-Token", csrf)
		workers.Go(func() {
			<-start
			w := httptest.NewRecorder()
			f.server.ServeHTTP(w, r)
			results <- w
		})
	}
	close(start)
	workers.Wait()
	close(results)
	success, conflict := 0, 0
	for response := range results {
		switch response.Code {
		case 200:
			success++
		case 409:
			conflict++
			assertErrorCode(t, response, "already_setup")
		default:
			t.Fatalf("concurrent setup status=%d body=%s", response.Code, response.Body.String())
		}
	}
	admins, err := f.store.ListAdmins(context.Background())
	if success != 1 || conflict != 1 || err != nil || len(admins) != 1 {
		t.Fatalf("success=%d conflict=%d admins=%+v err=%v", success, conflict, admins, err)
	}
}

func TestAllAdministratorResourceCRUDAndSecretRevealAudit(t *testing.T) {
	var upstreamAuthorization atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			io.WriteString(w, `{"data":[{"id":"native-model","name":"Native model","capabilities":{"chat_completions":true}}]}`)
			return
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"model":"native-model","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3}}`)
	}))
	defer upstream.Close()
	f := newGatewayFixture(t)
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	call := func(method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		return serve(t, f.server, a.request(t, method, path, body), want)
	}
	for _, resource := range []string{"engines", "models", "keys", "admins", "upstream-models", "settings", "dashboard", "statistics", "access-logs", "audit-logs", "backups"} {
		call("GET", "/admin/api/"+resource, nil, 200)
	}
	engineBody := map[string]any{"name": "Browser engine", "base_url": upstream.URL, "type": "auto", "auth_type": "bearer", "enabled": true, "secret": "private-upstream-secret"}
	w := call("POST", "/admin/api/engines", engineBody, 201)
	e := decodeResponse[domain.Engine](t, w)
	if e.ID == "" || !e.HasSecret || strings.Contains(w.Body.String(), "private-upstream-secret") {
		t.Fatalf("engine creation leaked credentials or lost state: %s", w.Body.String())
	}
	delete(engineBody, "secret")
	engineBody["name"] = "Renamed engine"
	call("PUT", "/admin/api/engines/"+e.ID, engineBody, 200)
	call("POST", "/admin/api/engines/"+e.ID+"/check", map[string]any{}, 200)
	if upstreamAuthorization.Load() != "Bearer private-upstream-secret" {
		t.Fatalf("blank engine credential edit did not preserve secret: %q", upstreamAuthorization.Load())
	}
	upstreams := decodeResponse[struct {
		Items []domain.UpstreamModel `json:"items"`
	}](t, call("GET", "/admin/api/upstream-models", nil, 200))
	if len(upstreams.Items) != 1 || upstreams.Items[0].Registered {
		t.Fatalf("discovery auto-registered model: %+v", upstreams)
	}
	key := decodeResponse[domain.APIKey](t, call("POST", "/admin/api/keys", map[string]any{"name": "Client", "enabled": true, "tags": []string{"qa"}}, 201))
	w = call("POST", "/admin/api/keys/"+key.ID+"/reveal", map[string]any{}, 200)
	revealed := decodeResponse[struct {
		Secret string `json:"secret"`
	}](t, w).Secret
	if !strings.HasPrefix(revealed, "llmgw_") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid secret reveal: %s", w.Body.String())
	}
	var reveals int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action='api_key.secret_viewed' AND target=? AND actor_id=?", key.ID, a.admin.ID).Scan(&reveals); err != nil || reveals != 1 {
		t.Fatalf("secret reveal audit count=%d err=%v", reveals, err)
	}
	for _, resource := range []string{"keys", "engines", "admins", "audit-logs"} {
		body := call("GET", "/admin/api/"+resource, nil, 200).Body.String()
		for _, forbidden := range []string{revealed, "private-upstream-secret", "password_hash", "secret_hash", "secret_cipher"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s leaked %q: %s", resource, forbidden, body)
			}
		}
	}
	model := decodeResponse[domain.Model](t, call("POST", "/admin/api/models", map[string]any{"alias": "public-model", "engine_id": e.ID, "upstream_model_id": "native-model", "published": true, "capabilities": allCapabilities()}, 201))
	if len(model.AllowedIPs) != 2 {
		t.Fatalf("model did not default to loopback ACL: %+v", model)
	}
	model.AllowedIPs = []string{}
	model.AllowedAPIKeys = []string{key.ID}
	model = decodeResponse[domain.Model](t, call("PUT", "/admin/api/models/"+model.ID, model, 200))
	r := requestJSON(t, "POST", "/v1/chat/completions", chatBody(model.Alias))
	r.RemoteAddr = "203.0.113.8:1234"
	r.Header.Set("Authorization", "Bearer "+revealed)
	serve(t, f.server, r, 200)
	call("DELETE", "/admin/api/keys/"+key.ID, nil, 409)
	call("DELETE", "/admin/api/engines/"+e.ID, nil, 409)
	call("PUT", "/admin/api/keys/"+key.ID, map[string]any{"name": "Disabled client", "enabled": false, "tags": []string{}}, 200)
	r = requestJSON(t, "POST", "/v1/chat/completions", chatBody(model.Alias))
	r.Header.Set("Authorization", "Bearer "+revealed)
	assertErrorCode(t, serve(t, f.server, r, 401), "unauthorized")
	model.Alias = "renamed-model"
	model.Published = false
	model = decodeResponse[domain.Model](t, call("PUT", "/admin/api/models/"+model.ID, model, 200))
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody("public-model")), 404), "model_not_found")
	assertErrorCode(t, serve(t, f.server, requestJSON(t, "POST", "/v1/chat/completions", chatBody(model.Alias)), 404), "model_not_found")
	settings := decodeResponse[domain.Settings](t, call("GET", "/admin/api/settings", nil, 200))
	settings.RequestTimeoutSeconds = 37
	call("PUT", "/admin/api/settings", settings, 200)
	settings = decodeResponse[domain.Settings](t, call("GET", "/admin/api/settings", nil, 200))
	if settings.RequestTimeoutSeconds != 37 {
		t.Fatal("settings edit did not persist")
	}
	additional := decodeResponse[domain.Admin](t, call("POST", "/admin/api/admins", map[string]string{"username": "additional", "password": "another-long-password"}, 201))
	call("PUT", "/admin/api/admins/"+additional.ID, map[string]string{"password": "replaced-long-password"}, 200)
	call("DELETE", "/admin/api/admins/"+additional.ID, nil, 200)
	call("DELETE", "/admin/api/admins/"+a.admin.ID, nil, 409)
	backup := decodeResponse[domain.Backup](t, call("POST", "/admin/api/backups", map[string]string{"kind": "local"}, 201))
	download := call("GET", "/admin/api/backups/"+backup.ID+"/download", nil, 200)
	if download.Body.Len() < 100 || !strings.Contains(download.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("backup download unavailable: headers=%v size=%d", download.Header(), download.Body.Len())
	}
	call("DELETE", "/admin/api/backups/"+backup.ID, nil, 200)
	call("GET", "/admin/api/backups/"+backup.ID+"/download", nil, 404)
	for _, resource := range []string{"dashboard", "statistics?group=model", "statistics?group=engine", "statistics?group=api_key", "access-logs?q=public-model", "audit-logs?q=created"} {
		call("GET", "/admin/api/"+resource, nil, 200)
	}
	model.AllowedAPIKeys = []string{}
	call("PUT", "/admin/api/models/"+model.ID, model, 200)
	call("DELETE", "/admin/api/keys/"+key.ID, nil, 200)
	call("DELETE", "/admin/api/models/"+model.ID, nil, 200)
	call("DELETE", "/admin/api/engines/"+e.ID, nil, 200)
	for _, resource := range []string{"keys", "models", "engines", "backups"} {
		result := decodeResponse[struct {
			Total int `json:"total"`
		}](t, call("GET", "/admin/api/"+resource, nil, 200))
		if result.Total != 0 {
			t.Fatalf("%s not deleted: total=%d", resource, result.Total)
		}
	}
}

func TestAdminAuthorizationAndRejectedSettingsDoNotMutate(t *testing.T) {
	f := newGatewayFixture(t)
	for _, path := range []string{"/admin/api/engines", "/admin/api/keys", "/admin/api/session", "/admin/api/settings", "/admin/api/backups"} {
		assertErrorCode(t, serve(t, f.server, requestJSON(t, "GET", path, nil), 401), "unauthorized")
	}
	f.key(t, "non-admin", "llmgw_not-an-administrator")
	r := requestJSON(t, "GET", "/admin/api/admins", nil)
	r.Header.Set("Authorization", "Bearer llmgw_not-an-administrator")
	assertErrorCode(t, serve(t, f.server, r, 401), "unauthorized")
	a := signIn(t, f, true, "owner", administratorPassword, nil)
	initial, err := f.store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	invalid := initial
	invalid.ListenAddress = "127.0.0.1:0"
	serve(t, f.server, a.request(t, "PUT", "/admin/api/settings", invalid), 400)
	got, err := f.store.Settings(context.Background())
	if err != nil || got != initial {
		t.Fatalf("invalid settings persisted: %+v err=%v", got, err)
	}
	called := false
	f.server.ApplySettings = func(context.Context, domain.Settings) error {
		called = true
		return fmt.Errorf("address already in use")
	}
	next := initial
	next.ListenAddress = "127.0.0.1:9009"
	w := serve(t, f.server, a.request(t, "PUT", "/admin/api/settings", next), 409)
	assertErrorCode(t, w, "settings_rejected")
	got, err = f.store.Settings(context.Background())
	if !called || err != nil || got != initial {
		t.Fatalf("failed listener update persisted settings: called=%v got=%+v err=%v", called, got, err)
	}
}

func TestAuditAfterCanceledRequestStillPersists(t *testing.T) {
	f := newGatewayFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := requestJSON(t, "POST", "/admin/api/engines", nil).WithContext(ctx)
	cancel()
	f.server.auditOK(r, domain.Admin{ID: "actor", Username: "owner"}, "engine.changed", "target")
	var count int
	err := f.store.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE actor_id='actor' AND action='engine.changed' AND target='target'").Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("completed change lost audit on request cancellation: count=%d err=%v", count, err)
	}
}
