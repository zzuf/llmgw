package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

const CookieName = "llmgw_session"
const preCookie = "llmgw_pre_csrf"

var ErrUnauthorized = errors.New("authentication required")

type Manager struct{ Store *database.Store }

func (m *Manager) NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, a domain.Admin) (string, error) {
	if c, e := r.Cookie(CookieName); e == nil {
		if e = m.Store.DeleteSession(ctx, cryptoutil.HashSecret(c.Value)); e != nil {
			return "", e
		}
	}
	token := cryptoutil.RandomID() + cryptoutil.RandomID()
	csrf := cryptoutil.RandomID() + cryptoutil.RandomID()
	now := time.Now().UTC()
	s := domain.Session{TokenHash: cryptoutil.HashSecret(token), AdminID: a.ID, CSRFToken: csrf, ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339Nano), CreatedAt: now.Format(time.RFC3339Nano)}
	if err := m.Store.PutSessionForAdmin(ctx, s, a.PasswordHash); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 86400})
	return csrf, nil
}
func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (domain.Admin, domain.Session, error) {
	c, e := r.Cookie(CookieName)
	if e != nil || len(c.Value) > 256 {
		return domain.Admin{}, domain.Session{}, ErrUnauthorized
	}
	s, e := m.Store.GetSession(ctx, cryptoutil.HashSecret(c.Value))
	if e != nil {
		return domain.Admin{}, s, ErrUnauthorized
	}
	a, e := m.Store.GetAdmin(ctx, s.AdminID)
	if e != nil {
		return a, s, ErrUnauthorized
	}
	return a, s, nil
}
func (m *Manager) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if c, e := r.Cookie(CookieName); e == nil {
		if e = m.Store.DeleteSession(ctx, cryptoutil.HashSecret(c.Value)); e != nil {
			return e
		}
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	return nil
}
func SameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func CSRF(r *http.Request, expected string) bool {
	got := r.Header.Get("X-CSRF-Token")
	return SameOrigin(r) && len(expected) >= 32 && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
func PreauthCSRF(w http.ResponseWriter, r *http.Request) string {
	token := ""
	if c, e := r.Cookie(preCookie); e == nil && len(c.Value) == 64 {
		token = c.Value
	}
	if token == "" {
		token = cryptoutil.RandomID() + cryptoutil.RandomID()
	}
	http.SetCookie(w, &http.Cookie{Name: preCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 1800})
	return token
}
func ValidPreauth(r *http.Request) bool {
	c, e := r.Cookie(preCookie)
	return e == nil && CSRF(r, c.Value)
}
