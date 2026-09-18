// Package keychain stores gateway master keys in the user's native macOS Keychain.
package keychain

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrNotFound means the directory has no stored master key.
	ErrNotFound = errors.New("master key not found in macOS Keychain")
	// ErrUnsupported means this build cannot access the native macOS Keychain.
	ErrUnsupported = errors.New("macOS Keychain requires macOS and cgo")
	// ErrExistingDataKeyMissing prevents accidentally replacing a lost master key.
	ErrExistingDataKeyMissing = errors.New("master key is missing for an existing database")
	// ErrInvalidKey means a stored key does not have the required 256-bit length.
	ErrInvalidKey    = errors.New("invalid master key in macOS Keychain")
	errAlreadyExists = errors.New("master key already exists")
)

const keySize = 32

type backend interface {
	read(account string) ([]byte, error)
	create(account string, key []byte) error
}

// Load returns the existing 256-bit master key scoped to dataDir. It never
// creates a key or writes a file, including when the key is missing.
func Load(dataDir string) ([]byte, error) {
	return load(dataDir, nativeBackend{})
}

// LoadOrCreate returns the existing master key or creates one in the user's
// macOS Keychain. Creation fails if a database or pending restore already exists.
// Callers must hold the data-directory process lock and invoke this before
// creating the database. There is no file or environment fallback.
func LoadOrCreate(dataDir string) ([]byte, error) {
	return loadOrCreate(dataDir, nativeBackend{}, rand.Reader)
}

func load(dataDir string, store backend) ([]byte, error) {
	_, account, err := directoryIdentity(dataDir)
	if err != nil {
		return nil, err
	}
	return readKey(store, account)
}

func loadOrCreate(dataDir string, store backend, random io.Reader) ([]byte, error) {
	dir, account, err := directoryIdentity(dataDir)
	if err != nil {
		return nil, err
	}
	key, err := readKey(store, account)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := checkNoExistingDatabase(dir); err != nil {
		return nil, err
	}
	key = make([]byte, keySize)
	if _, err := io.ReadFull(random, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := store.create(account, key); err != nil {
		clear(key)
		if errors.Is(err, errAlreadyExists) {
			// Another creator won. Never overwrite or return our losing key.
			return readKey(store, account)
		}
		return nil, fmt.Errorf("store master key: %w", err)
	}
	return key, nil
}

func readKey(store backend, account string) ([]byte, error) {
	key, err := store.read(account)
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("load master key: %w", err)
	}
	if len(key) != keySize {
		clear(key)
		return nil, ErrInvalidKey
	}
	return key, nil
}

func directoryIdentity(dataDir string) (string, string, error) {
	if dataDir == "" {
		return "", "", errors.New("data directory is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve data directory: %w", err)
	}
	// Resolve the existing ancestor so the identity remains stable when a new
	// directory is created, including when its parent is reached by a symlink.
	candidate := abs
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			info, err := os.Stat(resolved)
			if err != nil {
				return "", "", fmt.Errorf("inspect data directory: %w", err)
			}
			if !info.IsDir() {
				return "", "", errors.New("data directory or its ancestor is not a directory")
			}
			resolved, err = canonicalExistingDirectory(resolved)
			if err != nil {
				return "", "", fmt.Errorf("resolve canonical data directory: %w", err)
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			digest := sha256.Sum256([]byte(resolved))
			return resolved, fmt.Sprintf("v1:%x", digest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", "", fmt.Errorf("resolve data directory: %w", err)
		}
		if _, statErr := os.Lstat(candidate); statErr == nil {
			return "", "", fmt.Errorf("resolve data directory symlink: %w", err)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return "", "", fmt.Errorf("inspect data directory: %w", statErr)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", "", fmt.Errorf("resolve data directory: %w", err)
		}
		suffix = append(suffix, filepath.Base(candidate))
		candidate = parent
	}
}

func checkNoExistingDatabase(dataDir string) error {
	entries, err := os.ReadDir(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check for existing database: %w", err)
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if name == "pending-restore.bin" {
			return ErrExistingDataKeyMissing
		}
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			name = strings.TrimSuffix(name, suffix)
		}
		switch filepath.Ext(name) {
		case ".db", ".sqlite", ".sqlite3":
			return ErrExistingDataKeyMissing
		}
	}
	return nil
}
