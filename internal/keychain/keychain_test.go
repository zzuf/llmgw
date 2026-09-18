package keychain

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Tests inject this backend and never invoke the native Keychain backend.
type memoryBackend struct {
	mu        sync.Mutex
	keys      map[string][]byte
	readErr   error
	createErr error
}

func (m *memoryBackend) read(account string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErr != nil {
		return nil, m.readErr
	}
	key, ok := m.keys[account]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(key), nil
}

func (m *memoryBackend) create(account string, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	if _, ok := m.keys[account]; ok {
		return errAlreadyExists
	}
	if m.keys == nil {
		m.keys = make(map[string][]byte)
	}
	m.keys[account] = bytes.Clone(key)
	return nil
}

func TestLoadOrCreateKeepsSameKeyWithoutWritingFiles(t *testing.T) {
	dir := t.TempDir()
	store := &memoryBackend{}
	want, err := loadOrCreate(dir, store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 32 {
		t.Fatalf("key length = %d, want 32", len(want))
	}
	got, err := loadOrCreate(dir, store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("master key changed")
	}
	loaded, err := load(dir, store)
	if err != nil || !bytes.Equal(loaded, want) {
		t.Fatalf("Load failed: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatal("keychain package wrote files to the data directory")
	}
}

func TestDirectoryScopesSeparateKeysAndResolveSymlinks(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Fatal(err)
	}
	store := &memoryBackend{}
	want, err := loadOrCreate(filepath.Join(realDir, "new", "data"), store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadOrCreate(filepath.Join(alias, "new", "data"), store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("symlink alias used a different key")
	}
	if err := os.MkdirAll(filepath.Join(realDir, "new", "data"), 0700); err != nil {
		t.Fatal(err)
	}
	got, err = load(filepath.Join(alias, "new", "data"), store)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("directory creation changed identity: %v", err)
	}
	other, err := loadOrCreate(filepath.Join(root, "other"), store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(want, other) {
		t.Fatal("different data directories share a key")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, filepath.Join(realDir, "new", "data"))
	if err != nil {
		t.Fatal(err)
	}
	got, err = load(relative, store)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("relative path changed directory identity: %v", err)
	}
}

func TestExistingDatabaseUsesItsOriginalKey(t *testing.T) {
	dir := t.TempDir()
	store := &memoryBackend{}
	want, err := loadOrCreate(dir, store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "llmgw.db"), []byte("database fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadOrCreate(dir, store, rand.Reader)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("existing database could not use its key: %v", err)
	}
}

func TestMissingKeyNeverReplacesExistingDatabaseKey(t *testing.T) {
	for _, filename := range []string{"gateway.db", "gateway.db-wal", "gateway.db-shm", "llmgw.db", "data.sqlite", "data.sqlite3-journal", "pending-restore.bin"} {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, filename), []byte("database fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			store := &memoryBackend{}
			if _, err := loadOrCreate(dir, store, rand.Reader); !errors.Is(err, ErrExistingDataKeyMissing) {
				t.Fatalf("got %v, want missing existing key error", err)
			}
			if _, err := load(dir, store); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing key was replaced: %v", err)
			}
		})
	}
}

func TestLoadDoesNotCreateMissingKey(t *testing.T) {
	if _, err := load(t.TempDir(), &memoryBackend{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestInvalidStoredKeyIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	store := &memoryBackend{}
	if _, err := loadOrCreate(dir, store, rand.Reader); err != nil {
		t.Fatal(err)
	}
	for account := range store.keys {
		store.keys[account] = []byte("invalid")
	}
	if _, err := loadOrCreate(dir, store, rand.Reader); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("got %v, want invalid key", err)
	}
	if _, err := load(dir, store); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid key was replaced: %v", err)
	}
}

func TestKeychainFailureAndRandomFailureFailClosed(t *testing.T) {
	sentinel := errors.New("backend unavailable")
	for _, store := range []*memoryBackend{{readErr: sentinel}, {createErr: sentinel}} {
		dir := t.TempDir()
		if _, err := loadOrCreate(dir, store, rand.Reader); !errors.Is(err, sentinel) {
			t.Fatalf("got %v, want backend error", err)
		}
		if len(store.keys) != 0 {
			t.Fatal("created key after failure")
		}
	}
	store := &memoryBackend{}
	if _, err := loadOrCreate(t.TempDir(), store, bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want entropy failure", err)
	}
	if len(store.keys) != 0 {
		t.Fatal("created key after entropy failure")
	}
}

func TestConcurrentCreationReturnsOneWinningKey(t *testing.T) {
	dir := t.TempDir()
	store := &memoryBackend{}
	var wg sync.WaitGroup
	keys := make(chan []byte, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := loadOrCreate(dir, store, rand.Reader)
			if err != nil {
				t.Errorf("LoadOrCreate: %v", err)
				return
			}
			keys <- key
		}()
	}
	wg.Wait()
	close(keys)
	var want []byte
	for key := range keys {
		if want == nil {
			want = key
		}
		if !bytes.Equal(key, want) {
			t.Fatal("concurrent creators returned different keys")
		}
	}
}

type winningBackend struct {
	winningKey []byte
	created    bool
}

func (s *winningBackend) read(string) ([]byte, error) {
	if !s.created {
		return nil, ErrNotFound
	}
	return bytes.Clone(s.winningKey), nil
}

func (s *winningBackend) create(string, []byte) error {
	s.created = true
	return errAlreadyExists
}

func TestDuplicateInsertionReturnsStoredKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 32)
	store := &winningBackend{winningKey: want}
	got, err := loadOrCreate(t.TempDir(), store, bytes.NewReader(bytes.Repeat([]byte{0x12}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("returned generated key instead of the winning stored key")
	}
}

func TestInvalidDataDirectoryFailsBeforeCreatingKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", file, filepath.Join(file, "child")} {
		store := &memoryBackend{}
		if _, err := loadOrCreate(dir, store, rand.Reader); err == nil {
			t.Fatalf("accepted invalid directory %q", dir)
		}
		if len(store.keys) != 0 {
			t.Fatal("created key for an invalid data directory")
		}
	}
	dangling := filepath.Join(t.TempDir(), "dangling")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreate(filepath.Join(dangling, "child"), &memoryBackend{}, rand.Reader); err == nil {
		t.Fatal("accepted a dangling symlink as a directory")
	}
}
