package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

func fixture(t *testing.T, keyByte byte) (*database.Store, *Manager, domain.Engine, domain.APIKey) {
	t.Helper()
	dir := t.TempDir()
	s, err := database.Open(filepath.Join(dir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	m := New(s.DB, dir, bytes.Repeat([]byte{keyByte}, 32))
	ctx := context.Background()
	a := domain.Admin{Username: "admin", PasswordHash: "hashed-password"}
	if err = s.CreateAdmin(ctx, &a, true); err != nil {
		t.Fatal(err)
	}
	if err = s.PutSession(ctx, domain.Session{TokenHash: "live-session", AdminID: a.ID, CSRFToken: "live-csrf", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	e := domain.Engine{Name: "original", BaseURL: "http://127.0.0.1:1234", Type: "openai", AuthType: "bearer", Enabled: true}
	if err = s.SaveEngine(ctx, &e); err != nil {
		t.Fatal(err)
	}
	v, _ := cryptoutil.New(m.MasterKey)
	e.SecretCipher, err = v.Encrypt([]byte("engine-super-secret"), "engine:"+e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveEngine(ctx, &e); err != nil {
		t.Fatal(err)
	}
	k := domain.APIKey{ID: cryptoutil.RandomID(), Name: "client", SecretHash: cryptoutil.HashSecret("api-key-super-secret"), Suffix: "cret", Enabled: true}
	k.SecretCipher, err = v.Encrypt([]byte("api-key-super-secret"), "api-key:"+k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveAPIKey(ctx, &k); err != nil {
		t.Fatal(err)
	}
	return s, m, e, k
}

func TestSnapshotCapturesWALAndRestoreDiscardsSessions(t *testing.T) {
	s, m, e, _ := fixture(t, 1)
	ctx := context.Background()
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	path, err := m.Path(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
	e.Name = "changed after backup"
	if err = s.SaveEngine(ctx, &e); err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestore(ctx, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	current, err := s.GetEngine(ctx, e.ID)
	if err != nil || current.Name != "changed after backup" {
		t.Fatalf("staging mutated active data: %+v %v", current, err)
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil || count != 1 {
		t.Fatal("staging revoked live sessions")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(m.DataDir, m.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(m.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.GetEngine(ctx, e.ID)
	if err != nil || got.Name != "original" {
		t.Fatalf("restored=%+v %v", got, err)
	}
	if err = restored.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("restored stale sessions")
	}
	files, err := New(restored.DB, m.DataDir, m.MasterKey).List(ctx)
	if err != nil || len(files) < 2 {
		t.Fatalf("missing rollback snapshot: %v %v", files, err)
	}
}

func TestPortableBackupRewrapsBothSecretKinds(t *testing.T) {
	_, source, e, k := fixture(t, 1)
	ctx := context.Background()
	pass := "correct horse battery staple"
	b, err := source.Create(ctx, "portable", pass)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := source.Path(ctx, b.ID)
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{source.MasterKey, []byte("SQLite format 3"), []byte("engine-super-secret"), []byte("api-key-super-secret")} {
		if bytes.Contains(archive, secret) {
			t.Fatal("portable archive exposes plaintext")
		}
	}
	destStore, dest, _, _ := fixture(t, 2)
	if err = dest.StageUpload(ctx, bytes.NewReader(archive), "wrong passphrase"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	tampered := bytes.Clone(archive)
	tampered[len(tampered)-1] ^= 1
	if err = dest.StageUpload(ctx, bytes.NewReader(tampered), pass); err == nil {
		t.Fatal("tampered archive accepted")
	}
	if err = dest.StageUpload(ctx, bytes.NewReader(archive), pass); err != nil {
		t.Fatal(err)
	}
	if err = destStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(dest.DataDir, source.MasterKey); err == nil {
		t.Fatal("staged restore accepted wrong destination master")
	}
	if err = ApplyPending(dest.DataDir, dest.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(dest.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	v, _ := cryptoutil.New(dest.MasterKey)
	gotE, err := restored.GetEngine(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := v.Decrypt(gotE.SecretCipher, "engine:"+e.ID)
	if err != nil || string(plain) != "engine-super-secret" {
		t.Fatalf("engine rewrap: %q %v", plain, err)
	}
	gotK, err := restored.KeyByHash(ctx, k.SecretHash)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = v.Decrypt(gotK.SecretCipher, "api-key:"+k.ID)
	if err != nil || string(plain) != "api-key-super-secret" {
		t.Fatalf("API key rewrap: %q %v", plain, err)
	}
}

func TestInvalidRestoreLeavesActiveDatabaseIntact(t *testing.T) {
	s, m, e, _ := fixture(t, 3)
	ctx := context.Background()
	if err := m.StageUpload(ctx, bytes.NewBufferString("not a backup"), ""); err == nil {
		t.Fatal("invalid archive accepted")
	}
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	path, _ := m.Path(ctx, b.ID)
	other := New(s.DB, m.DataDir, bytes.Repeat([]byte{4}, 32))
	if err = other.StageRestore(ctx, b.ID, ""); err == nil {
		t.Fatal("local backup accepted wrong master")
	}
	bad, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Exec("INSERT INTO schema_migrations(version,applied_at) VALUES(999,'future')"); err != nil {
		t.Fatal(err)
	}
	bad.Close()
	if err = m.StageRestore(ctx, b.ID, ""); err == nil {
		t.Fatal("newer schema accepted")
	}
	got, err := s.GetEngine(ctx, e.ID)
	if err != nil || got.Name != "original" {
		t.Fatalf("active DB changed: %+v %v", got, err)
	}
	if _, err = os.Stat(filepath.Join(m.DataDir, "pending-restore.bin")); !os.IsNotExist(err) {
		t.Fatal("invalid archive was staged")
	}
}

func TestBackupPathsRejectTraversalAndSymlinksAndPruneOldFiles(t *testing.T) {
	_, m, _, _ := fixture(t, 5)
	ctx := context.Background()
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../llmgw", "", b.ID + ".sqlite", "../../secret"} {
		if _, err = m.Path(ctx, id); err == nil {
			t.Fatalf("unsafe ID accepted %q", id)
		}
	}
	linkID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err = os.Symlink(filepath.Join(m.DataDir, "llmgw.db"), filepath.Join(m.DataDir, "backups", linkID+".sqlite")); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Path(ctx, linkID); err == nil {
		t.Fatal("symlink accepted")
	}
	path, _ := m.Path(ctx, b.ID)
	old := time.Now().Add(-15 * 24 * time.Hour)
	if err = os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err = m.Prune(ctx, 14); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Path(ctx, b.ID); err == nil {
		t.Fatal("expired backup retained")
	}
	b, err = m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Delete(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Path(ctx, b.ID); err == nil {
		t.Fatal("backup not deleted")
	}
}

func TestRestoreRejectsTamperedCredentialsAndUnexpectedTriggers(t *testing.T) {
	_, m, _, _ := fixture(t, 6)
	ctx := context.Background()
	for _, mutation := range []string{
		"UPDATE engines SET secret_cipher=randomblob(80)",
		"CREATE TRIGGER unexpected AFTER UPDATE ON engines BEGIN DELETE FROM api_keys; END",
	} {
		b, err := m.Create(ctx, "local", "")
		if err != nil {
			t.Fatal(err)
		}
		path, _ := m.Path(ctx, b.ID)
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(mutation)
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = m.StageRestore(ctx, b.ID, ""); err == nil {
			t.Fatalf("unsafe backup accepted: %s", mutation)
		}
	}
}

func TestTamperedPendingRestoreLeavesDatabaseUnchanged(t *testing.T) {
	s, m, e, _ := fixture(t, 7)
	ctx := context.Background()
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestore(ctx, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	e.Name = "must survive rejected restoration"
	if err = s.SaveEngine(ctx, &e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.DataDir, pendingFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(m.DataDir, m.MasterKey); err == nil {
		t.Fatal("tampered staging was installed")
	}
	reopened, err := database.Open(filepath.Join(m.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetEngine(ctx, e.ID)
	if err != nil || got.Name != e.Name {
		t.Fatalf("original database was replaced: %+v %v", got, err)
	}
}

func TestDataDirectoryAliasUsesSameBackups(t *testing.T) {
	s, m, _, _ := fixture(t, 8)
	alias := filepath.Join(t.TempDir(), "data-alias")
	if err := os.Symlink(m.DataDir, alias); err != nil {
		t.Fatal(err)
	}
	viaAlias := New(s.DB, alias, m.MasterKey)
	b, err := viaAlias.Create(context.Background(), "local", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Path(context.Background(), b.ID); err != nil {
		t.Fatal("aliased directory has a different backup collection:", err)
	}
}

func TestValidRestoreRecoversCorruptDatabaseAndPreservesOriginalBytes(t *testing.T) {
	s, m, e, _ := fixture(t, 9)
	ctx := context.Background()
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestore(ctx, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	corrupted := []byte("the previous database is damaged")
	if err = os.WriteFile(filepath.Join(m.DataDir, "llmgw.db"), corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(m.DataDir, m.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(m.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got, err := restored.GetEngine(ctx, e.ID); err != nil || got.Name != "original" {
		t.Fatalf("recovery failed: %+v %v", got, err)
	}
	recoveries, err := filepath.Glob(filepath.Join(m.DataDir, "backups", "*.recovery", "llmgw.db"))
	if err != nil || len(recoveries) != 1 {
		t.Fatalf("damaged original missing: %v %v", recoveries, err)
	}
	data, err := os.ReadFile(recoveries[0])
	if err != nil || !bytes.Equal(data, corrupted) {
		t.Fatalf("damaged original changed: %q %v", data, err)
	}
}

func TestRestoreInitiatorAuditSurvivesInRestoredDatabase(t *testing.T) {
	s, m, _, _ := fixture(t, 10)
	ctx := context.Background()
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	audit := domain.Audit{ActorID: "administrator-after-backup", ActorName: "alice", SourceIP: "127.0.0.1", Action: "backup.restore_requested", Target: b.ID, Result: "success"}
	if err = s.AddAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestoreWithAudit(ctx, b.ID, "", audit); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(m.DataDir, m.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(m.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var actor, name, source, target string
	if err = restored.DB.QueryRow("SELECT actor_id,actor_name,source_ip,target FROM audit_logs WHERE action='backup.restored'").Scan(&actor, &name, &source, &target); err != nil {
		t.Fatal(err)
	}
	if actor != audit.ActorID || name != "alice" || source != "127.0.0.1" || target != b.ID {
		t.Fatalf("initiating actor lost: %q %q %q %q", actor, name, source, target)
	}
	var count int
	if err = restored.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action='backup.restore_applied' AND actor_name='system'").Scan(&count); err != nil || count != 1 {
		t.Fatal("installation audit missing")
	}
	items, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == b.ID {
			continue
		}
		path, err := m.Path(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		rollback, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		err = rollback.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action='backup.restore_requested' AND actor_name='alice'").Scan(&count)
		rollback.Close()
		if err != nil || count != 1 {
			t.Fatal("rollback lost outgoing audit")
		}
	}
}

func TestRequiredCredentialsCannotBeEmptyInBackupOrRestore(t *testing.T) {
	for _, tc := range []struct{ name, mutation string }{
		{"empty-api-key", "UPDATE api_keys SET secret_cipher=x''"},
		{"empty-bearer-engine", "UPDATE engines SET secret_cipher=x''"},
		{"null-bearer-engine", "UPDATE engines SET secret_cipher=NULL"},
		{"empty-api-key-engine", "UPDATE engines SET auth_type='x-api-key',secret_cipher=x''"},
		{"unknown-auth-type", "UPDATE engines SET auth_type='unsupported-auth'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m, _, _ := fixture(t, 15)
			ctx := context.Background()
			b, err := m.Create(ctx, "local", "")
			if err != nil {
				t.Fatal(err)
			}
			path, err := m.Path(ctx, b.ID)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = snapshot.Exec(tc.mutation)
			snapshot.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = m.StageRestore(ctx, b.ID, ""); err == nil {
				t.Fatal("restore accepted missing or unsupported credentials")
			}
			if _, err = os.Stat(filepath.Join(m.DataDir, pendingFilename)); !os.IsNotExist(err) {
				t.Fatal("invalid credentials were staged")
			}
			if _, err = s.DB.Exec(tc.mutation); err != nil {
				t.Fatal(err)
			}
			if _, err = m.Create(ctx, "local", ""); err == nil {
				t.Fatal("backup accepted missing or unsupported credentials")
			}
		})
	}
}

func TestUnauthenticatedEngineWithoutSecretCanBeBackedUpAndRestored(t *testing.T) {
	s, m, e, _ := fixture(t, 16)
	ctx := context.Background()
	if _, err := s.DB.Exec("UPDATE engines SET auth_type='none',secret_cipher=NULL"); err != nil {
		t.Fatal(err)
	}
	b, err := m.Create(ctx, "local", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.StageRestore(ctx, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ApplyPending(m.DataDir, m.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(m.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.GetEngine(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthType != "none" || len(got.SecretCipher) != 0 {
		t.Fatalf("unauthenticated engine changed: %+v", got)
	}
}
