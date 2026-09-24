package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"llmgw/internal/domain"
)

func TestV1MigrationPreservesKeysWithSafeguardsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);` + string(initial) + `INSERT INTO schema_migrations VALUES(1,'original'); INSERT INTO api_keys(id,name,secret_cipher,secret_hash,suffix,created_at,updated_at) VALUES('key','existing',x'0102','hash','abcd','before','before')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key, err := s.GetAPIKey(context.Background(), "key")
	if err != nil {
		t.Fatal(err)
	}
	if key.InputSafeguardID != nil || key.OutputSafeguardID != nil || key.BlockControversial || key.SecretHash != "hash" {
		t.Fatalf("migration changed key: %+v", key)
	}
	var columns int
	if err = s.DB.QueryRow(`SELECT count(*) FROM pragma_table_info('api_keys') WHERE name IN ('input_safeguard_id','output_safeguard_id','block_controversial')`).Scan(&columns); err != nil || columns != 3 {
		t.Fatalf("missing safeguard migration: %d %v", columns, err)
	}
	settings, err := s.Settings(context.Background())
	if err != nil || settings.GuardTimeoutSeconds != 60 || settings.GuardMaxTextBytes != 256<<10 || settings.GuardMaxSpoolBytes != 64<<20 {
		t.Fatalf("settings: %+v %v", settings, err)
	}
}

func TestSafeguardReferencesAndAvailability(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	e := seedEngine(t, s)
	g := domain.Safeguard{Name: "guard", EngineID: e.ID, UpstreamModelID: "native", Adapter: "qwen3guard_gen", Enabled: true}
	if err := s.SaveSafeguard(ctx, &g); err != nil {
		t.Fatal(err)
	}
	if !g.Available || g.ID == "" {
		t.Fatalf("guard not initialized: %+v", g)
	}
	key := domain.APIKey{Name: "guarded", SecretCipher: []byte("cipher"), SecretHash: "hash", Enabled: true, InputSafeguardID: &g.ID, OutputSafeguardID: &g.ID, BlockControversial: true}
	if err := s.SaveAPIKey(ctx, &key); err != nil {
		t.Fatal(err)
	}
	for _, load := range []func() (domain.APIKey, error){func() (domain.APIKey, error) { return s.GetAPIKey(ctx, key.ID) }, func() (domain.APIKey, error) { return s.KeyByHash(ctx, "hash") }, func() (domain.APIKey, error) {
		items, err := s.ListAPIKeys(ctx)
		if err != nil {
			return domain.APIKey{}, err
		}
		return items[0], nil
	}} {
		got, err := load()
		if err != nil || got.InputSafeguardID == nil || *got.InputSafeguardID != g.ID || got.OutputSafeguardID == nil || !got.BlockControversial {
			t.Fatalf("policy lost: %+v %v", got, err)
		}
	}
	if err := s.DeleteSafeguard(ctx, g.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("guard referenced: %v", err)
	}
	if err := s.DeleteEngine(ctx, e.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("engine referenced: %v", err)
	}
	if err := s.SyncModels(ctx, e.ID, nil); err != nil {
		t.Fatal(err)
	}
	missing, err := s.GetSafeguard(ctx, g.ID)
	if err != nil || missing.Available {
		t.Fatalf("missing guard %+v %v", missing, err)
	}
	if err := s.SyncModels(ctx, e.ID, []domain.UpstreamModel{{UpstreamID: "native"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSafeguardCheck(ctx, g.ID, "checked", "failure"); err != nil {
		t.Fatal(err)
	}
	g.Enabled = false
	g.LastCheck = "overwrite"
	g.LastError = "overwrite"
	if err := s.SaveSafeguard(ctx, &g); err != nil {
		t.Fatal(err)
	}
	if !g.Available || g.LastCheck != "checked" || g.LastError != "failure" {
		t.Fatalf("check state lost: %+v", g)
	}
	key.Enabled = false
	if err := s.SaveAPIKey(ctx, &key); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAPIKey(ctx, key.ID)
	if err != nil || got.InputSafeguardID == nil {
		t.Fatalf("disabled key lost policy: %+v %v", got, err)
	}
	key.InputSafeguardID = nil
	key.OutputSafeguardID = nil
	key.BlockControversial = false
	if err := s.SaveAPIKey(ctx, &key); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSafeguard(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSafeguard(ctx, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestSafeguardValidationAndSnapshot(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	e := seedEngine(t, s)
	g := domain.Safeguard{Name: "guard", EngineID: e.ID, UpstreamModelID: "native", Adapter: "qwen3guard_gen", Enabled: true}
	for _, mutate := range []func(*domain.Safeguard){func(v *domain.Safeguard) { v.Name = " " }, func(v *domain.Safeguard) { v.Adapter = "unknown" }, func(v *domain.Safeguard) { v.UpstreamModelID = "absent" }, func(v *domain.Safeguard) { v.EngineID = "absent" }} {
		invalid := g
		mutate(&invalid)
		if err := s.SaveSafeguard(ctx, &invalid); err == nil {
			t.Fatalf("invalid guard accepted: %+v", invalid)
		}
	}
	if err := s.SaveSafeguard(ctx, &g); err != nil {
		t.Fatal(err)
	}
	bindings, err := s.LoadSafeguards(ctx, []string{g.ID, g.ID})
	if err != nil || len(bindings) != 1 {
		t.Fatalf("load: %+v %v", bindings, err)
	}
	g.Enabled = false
	e.Name = "updated"
	e.Enabled = false
	if err := s.SaveSafeguard(ctx, &g); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEngine(ctx, &e); err != nil {
		t.Fatal(err)
	}
	old := bindings[g.ID]
	if !old.Safeguard.Enabled || !old.Engine.Enabled || old.Engine.Name == "updated" {
		t.Fatalf("snapshot mutated: %+v", old)
	}
	latest, err := s.LoadSafeguards(ctx, []string{g.ID})
	if err != nil || latest[g.ID].Safeguard.Enabled || latest[g.ID].Engine.Enabled {
		t.Fatalf("new snapshot stale: %+v %v", latest, err)
	}
	if _, err := s.LoadSafeguards(ctx, []string{"absent"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing reference: %v", err)
	}
	all, err := s.ListSafeguards(ctx)
	if err != nil || len(all) != 1 || all[0].Name != "guard" {
		t.Fatalf("list: %+v %v", all, err)
	}
}
