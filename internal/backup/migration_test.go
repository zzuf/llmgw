package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

// This fixture executes the immutable v1 migration, without opening it through
// the current Store (which would migrate before the restore code is exercised).
func legacySnapshot(t *testing.T, master []byte, mutation string) []byte {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_initial.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);` + string(initial) + `INSERT INTO schema_migrations VALUES(1,'original')`); err != nil {
		t.Fatal(err)
	}
	vault, err := cryptoutil.New(master)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.Encrypt([]byte("old-engine-secret"), "engine:old-engine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO engines(id,name,base_url,auth_type,secret_cipher,created_at,updated_at) VALUES('old-engine','Old engine','http://localhost:1234','bearer',?,'original','original')`, cipher); err != nil {
		t.Fatal(err)
	}
	cipher, err = vault.Encrypt([]byte("old-key-secret"), "api-key:old-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO api_keys(id,name,secret_cipher,secret_hash,suffix,created_at,updated_at) VALUES('old-key','Old key',?,'hash','cret','original','original')`, cipher); err != nil {
		t.Fatal(err)
	}
	if err = writeAuthentication(ctx, db, master); err != nil {
		t.Fatal(err)
	}
	if mutation != "" {
		if _, err = db.Exec(mutation); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func TestLegacyLocalAndPortableBackupsMigrateAfterAuthentication(t *testing.T) {
	for _, kind := range []string{"local", "portable"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store, destination, _, _ := fixture(t, 7)
			sourceMaster := destination.MasterKey
			if kind == "portable" {
				sourceMaster = bytes.Repeat([]byte{8}, 32)
			}
			archive := legacySnapshot(t, sourceMaster, "")
			passphrase := "migration passphrase"
			var err error
			if kind == "portable" {
				archive, err = encodePortable(archive, sourceMaster, passphrase)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = destination.StageUpload(ctx, bytes.NewReader(archive), passphrase); err != nil {
				t.Fatal(err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			if err = ApplyPending(destination.DataDir, destination.MasterKey); err != nil {
				t.Fatal(err)
			}
			restored, err := database.Open(filepath.Join(destination.DataDir, "llmgw.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			var version int
			if err = restored.DB.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != database.SchemaVersion {
				t.Fatalf("not migrated: %d %v", version, err)
			}
			key, err := restored.GetAPIKey(ctx, "old-key")
			if err != nil {
				t.Fatal(err)
			}
			if key.InputSafeguardID != nil || key.OutputSafeguardID != nil || key.BlockControversial {
				t.Fatalf("legacy policy was enabled: %+v", key)
			}
			vault, _ := cryptoutil.New(destination.MasterKey)
			plain, err := vault.Decrypt(key.SecretCipher, "api-key:old-key")
			if err != nil || string(plain) != "old-key-secret" {
				t.Fatalf("key rewrap failed: %v", err)
			}
			e, err := restored.GetEngine(ctx, "old-engine")
			if err != nil {
				t.Fatal(err)
			}
			plain, err = vault.Decrypt(e.SecretCipher, "engine:old-engine")
			if err != nil || string(plain) != "old-engine-secret" {
				t.Fatalf("engine rewrap failed: %v", err)
			}
			settings, err := restored.Settings(ctx)
			if err != nil || settings.GuardTimeoutSeconds != 60 {
				t.Fatalf("migration settings: %+v %v", settings, err)
			}
		})
	}
}

func TestLegacyBackupRejectsWrongKeyAndSchemaTampering(t *testing.T) {
	_, destination, _, _ := fixture(t, 9)
	ctx := context.Background()
	for _, tc := range []struct {
		name, mutation string
		master         []byte
	}{
		{"wrong master", "", bytes.Repeat([]byte{1}, 32)},
		{"trigger", `CREATE TRIGGER evil AFTER UPDATE ON api_keys BEGIN DELETE FROM engines; END`, destination.MasterKey},
		{"schema masquerade", `CREATE TABLE safeguards(id TEXT)`, destination.MasterKey},
		{"false version", `INSERT INTO schema_migrations VALUES(2,'fake')`, destination.MasterKey},
		{"bad secret", `UPDATE api_keys SET secret_cipher=randomblob(80)`, destination.MasterKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := legacySnapshot(t, tc.master, tc.mutation)
			if err := destination.StageUpload(ctx, bytes.NewReader(archive), ""); err == nil {
				t.Fatal("invalid legacy backup accepted")
			}
			if _, err := os.Stat(filepath.Join(destination.DataDir, pendingFilename)); !os.IsNotExist(err) {
				t.Fatal("invalid backup staged")
			}
		})
	}
}

func TestPendingLegacyRestoreIsMigrated(t *testing.T) {
	store, destination, _, _ := fixture(t, 11)
	archive := legacySnapshot(t, destination.MasterKey, "")
	vault, _ := cryptoutil.New(destination.MasterKey)
	cipher, err := vault.Encrypt(archive, pendingMagic)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(destination.DataDir, pendingFilename), append([]byte(pendingMagic), cipher...), 0600); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if err = ApplyPending(destination.DataDir, destination.MasterKey); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(filepath.Join(destination.DataDir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err = restored.GetAPIKey(context.Background(), "old-key"); err != nil {
		t.Fatal(err)
	}
}

func TestSafeguardsSurviveLocalAndPortableRestore(t *testing.T) {
	for _, kind := range []string{"local", "portable"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			sourceStore, source, e, key := fixture(t, 12)
			if err := sourceStore.SyncModels(ctx, e.ID, []domain.UpstreamModel{{UpstreamID: "guard-model"}}); err != nil {
				t.Fatal(err)
			}
			guard := domain.Safeguard{Name: "Guard", EngineID: e.ID, UpstreamModelID: "guard-model", Adapter: "qwen3guard_gen", Enabled: true}
			if err := sourceStore.SaveSafeguard(ctx, &guard); err != nil {
				t.Fatal(err)
			}
			key.InputSafeguardID = &guard.ID
			key.OutputSafeguardID = &guard.ID
			key.BlockControversial = true
			if err := sourceStore.SaveAPIKey(ctx, &key); err != nil {
				t.Fatal(err)
			}
			passphrase := "portable guard passphrase"
			b, err := source.Create(ctx, kind, passphrase)
			if err != nil {
				t.Fatal(err)
			}
			path, _ := source.Path(ctx, b.ID)
			archive, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			keyByte := byte(12)
			if kind == "portable" {
				keyByte = 13
			}
			destStore, dest, _, _ := fixture(t, keyByte)
			if err = dest.StageUpload(ctx, bytes.NewReader(archive), passphrase); err != nil {
				t.Fatal(err)
			}
			destStore.Close()
			if err = ApplyPending(dest.DataDir, dest.MasterKey); err != nil {
				t.Fatal(err)
			}
			restored, err := database.Open(filepath.Join(dest.DataDir, "llmgw.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			got, err := restored.GetAPIKey(ctx, key.ID)
			if err != nil || got.InputSafeguardID == nil || *got.InputSafeguardID != guard.ID || got.OutputSafeguardID == nil || !got.BlockControversial {
				t.Fatalf("guard policy not restored: %+v %v", got, err)
			}
			bindings, err := restored.LoadSafeguards(ctx, []string{guard.ID})
			if err != nil || !bindings[guard.ID].Safeguard.Available {
				t.Fatalf("binding not restored: %+v %v", bindings, err)
			}
		})
	}
}
