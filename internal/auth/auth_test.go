package auth

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"llmgw/internal/database"
	"llmgw/internal/domain"
)

func TestPasswordChangeRejectsSessionFromStaleVerifiedAdministrator(t *testing.T) {
	store, err := database.Open(filepath.Join(t.TempDir(), "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := domain.Admin{Username: "admin", PasswordHash: "verified-old-hash"}
	if err := store.CreateAdmin(context.Background(), &admin, true); err != nil {
		t.Fatal(err)
	}
	if err := store.ChangePassword(context.Background(), admin.ID, "new-password-hash"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://localhost/admin/api/login", nil)
	if _, err := (&Manager{Store: store}).NewSession(context.Background(), w, r, admin); err == nil {
		t.Fatal("created session using a password verified before revocation")
	}
	var count int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatalf("session count=%d err=%v", count, err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("failed session creation emitted a session cookie")
	}
}
