package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"llmgw/internal/backup"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/logging"
)

type gatewayFixture struct {
	server *Server
	store  *database.Store
	logs   *logging.Logger
	dir    string
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := database.Open(filepath.Join(dir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	vault, err := cryptoutil.New(master)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.New(store.DB, dir, domain.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logs.Close(); err != nil {
			t.Error(err)
		}
	})
	server := New(store, vault, logs, backup.New(store.DB, dir, master))
	return &gatewayFixture{server: server, store: store, logs: logs, dir: dir}
}

func (f *gatewayFixture) engine(t *testing.T, base, secret string) domain.Engine {
	t.Helper()
	e := domain.Engine{ID: cryptoutil.RandomID(), Name: "Mock engine", BaseURL: base, Type: "generic", AuthType: "none", Enabled: true, Status: "Online"}
	if secret != "" {
		e.AuthType = "bearer"
		var err error
		e.SecretCipher, err = f.server.Vault.Encrypt([]byte(secret), "engine:"+e.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.SaveEngine(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SyncModels(context.Background(), e.ID, []domain.UpstreamModel{{UpstreamID: "native-model", DisplayName: "Native", Capabilities: allCapabilities()}}); err != nil {
		t.Fatal(err)
	}
	return e
}

func allCapabilities() map[string]bool {
	return map[string]bool{"models": true, "chat_completions": true, "responses": true, "completions": true, "embeddings": true, "rerank": true, "messages": true, "streaming": true, "tools": true, "vision": true}
}

func (f *gatewayFixture) model(t *testing.T, e domain.Engine, alias string, ips, keys []string) domain.Model {
	t.Helper()
	m := domain.Model{Alias: alias, EngineID: e.ID, UpstreamModelID: "native-model", Published: true, AllowedIPs: ips, AllowedAPIKeys: keys, Capabilities: allCapabilities()}
	if err := f.store.SaveModel(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *gatewayFixture) key(t *testing.T, name, secret string) domain.APIKey {
	t.Helper()
	k := domain.APIKey{ID: cryptoutil.RandomID(), Name: name, SecretHash: cryptoutil.HashSecret(secret), Suffix: secret[len(secret)-4:], Enabled: true, Tags: []string{"integration"}}
	var err error
	k.SecretCipher, err = f.server.Vault.Encrypt([]byte(secret), "api-key:"+k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveAPIKey(context.Background(), &k); err != nil {
		t.Fatal(err)
	}
	return k
}

func requestJSON(t *testing.T, method, path string, value any) *http.Request {
	t.Helper()
	var body []byte
	if value != nil {
		var err error
		body, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "http://localhost:8080"+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:49152"
	r.Header.Set("Content-Type", "application/json")
	return r
}

func serve(t *testing.T, s *Server, r *http.Request, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: status=%d want=%d body=%s", r.Method, r.URL.Path, w.Code, want, w.Body.String())
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("response has no request ID")
	}
	return w
}

func decodeResponse[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return result
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	var result struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error.Code != want {
		t.Fatalf("error=%s want=%s body=%s", result.Error.Code, want, w.Body.String())
	}
}

func chatBody(alias string) map[string]any {
	return map[string]any{"model": alias, "messages": []any{map[string]any{"role": "user", "content": "Hello"}}}
}

func (f *gatewayFixture) accessRecords(t *testing.T) []domain.AccessRecord {
	t.Helper()
	if err := f.logs.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, _, err := logging.AccessLogs(context.Background(), f.store.DB, "", 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	return records
}
