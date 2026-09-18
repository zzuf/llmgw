package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "private", "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedEngine(t *testing.T, s *Store) domain.Engine {
	t.Helper()
	e := domain.Engine{Name: "Local", BaseURL: "http://127.0.0.1:1234", Type: "auto", AuthType: "none", Enabled: true}
	if err := s.SaveEngine(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncModels(context.Background(), e.ID, []domain.UpstreamModel{{UpstreamID: "native", DisplayName: "Native", Capabilities: map[string]bool{"chat": true, "streaming": true}}}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOpenMigratesIdempotentlyAndKeepsSecretsPrivate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	settings, err := s.Settings(ctx)
	if err != nil || settings.ListenAddress != "0.0.0.0:8080" || settings.RequestTimeoutSeconds != 600 || !settings.AutoBackupEnabled {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
	settings.ListenAddress = "127.0.0.1:9876"
	if err := s.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	path := s.Path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Settings(ctx)
	if err != nil || got.ListenAddress != "127.0.0.1:9876" {
		t.Fatalf("persisted settings=%+v err=%v", got, err)
	}
	for p, want := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions %s: %v err=%v", p, info, err)
		}
	}
	var fk int
	if err := reopened.DB.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys=%d err=%v", fk, err)
	}
	if _, err := reopened.DB.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES(999, 'future')"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(path); err == nil {
		bad.Close()
		t.Fatal("opened a newer schema")
	}
}

func TestModelDefaultsAliasUniquenessAndExplicitEmptyACL(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	e := seedEngine(t, s)
	m := domain.Model{Alias: "public-alias", EngineID: e.ID, UpstreamModelID: "native", Published: true}
	if err := s.SaveModel(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if m.ID == "" || !m.Available || !m.Capabilities["chat"] || !reflect.DeepEqual(m.AllowedIPs, []string{"127.0.0.1/32", "::1/128"}) {
		t.Fatalf("defaults=%+v", m)
	}
	duplicate := domain.Model{Alias: m.Alias, EngineID: e.ID, UpstreamModelID: "native"}
	if err := s.SaveModel(ctx, &duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate alias: %v", err)
	}
	for _, alias := range []string{"", "spaces here", "line\nbreak"} {
		bad := domain.Model{Alias: alias, EngineID: e.ID, UpstreamModelID: "native"}
		if err := s.SaveModel(ctx, &bad); err == nil {
			t.Fatalf("accepted alias %q", alias)
		}
	}
	m.AllowedIPs = []string{}
	if err := s.SaveModel(ctx, &m); err != nil {
		t.Fatal(err)
	}
	got, err := s.ModelByAlias(ctx, m.Alias)
	if err != nil || got.AllowedIPs == nil || len(got.AllowedIPs) != 0 {
		t.Fatalf("explicit empty ACL=%v err=%v", got.AllowedIPs, err)
	}
	m.AllowedIPs = []string{"not-an-ip"}
	if err := s.SaveModel(ctx, &m); err == nil {
		t.Fatal("accepted invalid CIDR")
	}
	m.AllowedIPs = []string{"::ffff:127.0.0.1", "192.168.7.12/24"}
	if err := s.SaveModel(ctx, &m); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetModel(ctx, m.ID)
	if err != nil || !reflect.DeepEqual(got.AllowedIPs, []string{"127.0.0.1/32", "192.168.7.0/24"}) {
		t.Fatalf("canonical ACL=%v err=%v", got.AllowedIPs, err)
	}
	missing := domain.Model{Alias: "missing", EngineID: e.ID, UpstreamModelID: "never-discovered"}
	if err := s.SaveModel(ctx, &missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("registered missing upstream: %v", err)
	}
}

func TestReferenceDeletionCannotAccidentallyPublishModel(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	e := seedEngine(t, s)
	k := domain.APIKey{Name: "Team", SecretHash: "hash", SecretCipher: []byte("cipher"), Suffix: "1234", Enabled: true, Tags: []string{"team", "team", "research"}}
	if err := s.SaveAPIKey(ctx, &k); err != nil {
		t.Fatal(err)
	}
	m := domain.Model{Alias: "private", EngineID: e.ID, UpstreamModelID: "native", AllowedAPIKeys: []string{k.ID}}
	if err := s.SaveModel(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAPIKey(ctx, k.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("referenced key deletion=%v", err)
	}
	if err := s.DeleteEngine(ctx, e.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("referenced engine deletion=%v", err)
	}
	m.AllowedAPIKeys = []string{"missing-key"}
	if err := s.SaveModel(ctx, &m); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing key=%v", err)
	}
	stored, err := s.GetModel(ctx, m.ID)
	if err != nil || !reflect.DeepEqual(stored.AllowedAPIKeys, []string{k.ID}) {
		t.Fatalf("ACL changed after rejected update: %+v err=%v", stored, err)
	}
	if err := s.TouchAPIKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.KeyByHash(ctx, "hash")
	if err != nil || got.LastUsedAt == "" || got.Masked == "" || !reflect.DeepEqual(got.Tags, []string{"research", "team"}) {
		t.Fatalf("key=%+v err=%v", got, err)
	}
	if err := s.DeleteModel(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAPIKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEngine(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	upstreams, err := s.ListUpstreamModels(ctx)
	if err != nil || len(upstreams) != 0 {
		t.Fatalf("orphan upstreams=%+v err=%v", upstreams, err)
	}
}

func TestSyncDisappearanceAndReturnPreservesPublicationACLAndOverrides(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	e := seedEngine(t, s)
	m := domain.Model{Alias: "stable", EngineID: e.ID, UpstreamModelID: "native", Published: true, AllowedIPs: []string{"10.0.0.0/8"}, Capabilities: map[string]bool{"chat": false, "vision": true}}
	if err := s.SaveModel(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncModels(ctx, e.ID, nil); err != nil {
		t.Fatal(err)
	}
	missing, err := s.GetModel(ctx, m.ID)
	if err != nil || missing.Available {
		t.Fatalf("missing model=%+v err=%v", missing, err)
	}
	if err := s.SyncModels(ctx, e.ID, []domain.UpstreamModel{{UpstreamID: "native", Capabilities: map[string]bool{"chat": true}}, {UpstreamID: "new"}}); err != nil {
		t.Fatal(err)
	}
	returned, err := s.GetModel(ctx, m.ID)
	if err != nil || !returned.Available || !returned.Published || returned.Alias != "stable" || !reflect.DeepEqual(returned.AllowedIPs, []string{"10.0.0.0/8"}) || returned.Capabilities["chat"] || !returned.Capabilities["vision"] {
		t.Fatalf("returned=%+v err=%v", returned, err)
	}
	models, err := s.ListModels(ctx)
	if err != nil || len(models) != 1 {
		t.Fatalf("sync auto-registered models=%+v err=%v", models, err)
	}
	upstreams, err := s.ListUpstreamModels(ctx)
	if err != nil || len(upstreams) != 2 || !upstreams[0].Registered || upstreams[1].Registered {
		t.Fatalf("upstream registration=%+v err=%v", upstreams, err)
	}
}

func TestFirstAdministratorIsAtomicAndFinalAdministratorSurvives(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, username := range []string{"first", "second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			a := domain.Admin{Username: name, PasswordHash: "hash"}
			errs <- s.CreateAdmin(ctx, &a, true)
		}(username)
	}
	wg.Wait()
	close(errs)
	successes, already := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrAlreadySetup) {
			already++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || already != 1 {
		t.Fatalf("success=%d already=%d", successes, already)
	}
	admins, err := s.ListAdmins(ctx)
	if err != nil || len(admins) != 1 {
		t.Fatalf("admins=%+v err=%v", admins, err)
	}
	if err := s.DeleteAdmin(ctx, admins[0].ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("final admin deletion=%v", err)
	}
	other := domain.Admin{Username: "additional", PasswordHash: "hash"}
	if err := s.CreateAdmin(ctx, &other, false); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSessionsExpireAndPasswordChangesRevokeThem(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := domain.Admin{Username: "admin", PasswordHash: "before"}
	if err := s.CreateAdmin(ctx, &a, true); err != nil {
		t.Fatal(err)
	}
	valid := domain.Session{TokenHash: "valid", AdminID: a.ID, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	if err := s.PutSession(ctx, valid); err != nil {
		t.Fatal(err)
	}
	expired := valid
	expired.TokenHash = "expired"
	expired.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if err := s.PutSession(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetSession(ctx, valid.TokenHash); err != nil || got.CSRFToken != "csrf" {
		t.Fatalf("valid session=%+v err=%v", got, err)
	}
	if _, err := s.GetSession(ctx, expired.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session=%v", err)
	}
	if err := s.ChangePassword(ctx, a.ID, "after"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, valid.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session survived password change: %v", err)
	}
	got, err := s.AdminByUsername(ctx, "admin")
	if err != nil || got.PasswordHash != "after" {
		t.Fatalf("admin=%+v err=%v", got, err)
	}
}

func TestPolicyReadNeverLosesACLDuringConcurrentDeletion(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e := seedEngine(t, s)
	key := domain.APIKey{Name: "Restricted", SecretHash: "restrict-hash", SecretCipher: []byte("cipher"), Enabled: true}
	if err := s.SaveAPIKey(ctx, &key); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	errs := make(chan error, 2)
	var readers sync.WaitGroup
	for range 2 {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				model, err := s.ModelByAlias(ctx, "changing")
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				if len(model.AllowedIPs) == 0 || len(model.AllowedAPIKeys) == 0 {
					errs <- errors.New("concurrent deletion removed a returned model's ACL")
					return
				}
			}
		})
	}
	for range 150 {
		model := domain.Model{Alias: "changing", EngineID: e.ID, UpstreamModelID: "native", AllowedAPIKeys: []string{key.ID}}
		if err := s.SaveModel(ctx, &model); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteModel(ctx, model.ID); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestFirstAdministratorIsAtomicAcrossDatabaseHandles(t *testing.T) {
	s := testStore(t)
	other, err := Open(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, store := range []*Store{s, other} {
		go func(i int, store *Store) {
			<-start
			a := domain.Admin{Username: []string{"one", "two"}[i], PasswordHash: "hash"}
			errs <- store.CreateAdmin(context.Background(), &a, true)
		}(i, store)
	}
	close(start)
	first, second := <-errs, <-errs
	if !((first == nil && errors.Is(second, ErrAlreadySetup)) || (second == nil && errors.Is(first, ErrAlreadySetup))) {
		t.Fatalf("first=%v second=%v", first, second)
	}
}
