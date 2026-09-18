// Package backup creates consistent SQLite snapshots and stages validated restoration.
// ApplyPending must run under the application's exclusive process lock before opening its DB.
package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/domain"
)

type Manager struct {
	DB        *sql.DB
	DataDir   string
	MasterKey []byte
	mu        sync.Mutex
}

func New(db *sql.DB, dataDir string, master []byte) *Manager {
	return &Manager{DB: db, DataDir: dataDir, MasterKey: append([]byte(nil), master...)}
}

var validID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup directory must be a real directory")
	}
	return os.Chmod(path, 0700)
}

func (m *Manager) directory() (string, error) {
	if m.DataDir == "" {
		return "", errors.New("data directory is required")
	}
	if err := os.MkdirAll(m.DataDir, 0700); err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(m.DataDir)
	if err != nil {
		return "", err
	}
	if err := privateDirectory(canonical); err != nil {
		return "", err
	}
	dir := filepath.Join(canonical, "backups")
	if err := privateDirectory(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func (m *Manager) Create(ctx context.Context, kind, passphrase string) (domain.Backup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.create(ctx, kind, passphrase)
}

func (m *Manager) create(ctx context.Context, kind, passphrase string) (domain.Backup, error) {
	var result domain.Backup
	if kind != "local" && kind != "portable" {
		return result, errors.New("backup kind must be local or portable")
	}
	if m.DB == nil {
		return result, errors.New("database is not open")
	}
	dir, err := m.directory()
	if err != nil {
		return result, err
	}
	path, err := m.snapshot(ctx)
	if err != nil {
		return result, err
	}
	defer removeSnapshot(path)
	snapshotInfo, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	if snapshotInfo.Size() > maxSnapshotSize {
		return result, errors.New("database snapshot exceeds backup size limit of 512 MiB")
	}
	id := cryptoutil.RandomID()
	extension := ".sqlite"
	if kind == "portable" {
		extension = ".llmgwb"
	}
	target := filepath.Join(dir, id+extension)
	if kind == "portable" {
		f, err := os.Open(path)
		if err != nil {
			return result, err
		}
		data, err := readBounded(f)
		f.Close()
		if err != nil {
			return result, err
		}
		defer clear(data)
		archive, err := encodePortable(data, m.MasterKey, passphrase)
		if err != nil {
			return result, err
		}
		if int64(len(archive)) > maxArchiveSize {
			return result, errors.New("portable backup exceeds 512 MiB limit")
		}
		if err = atomicWrite(target, archive); err != nil {
			return result, err
		}
	} else {
		if err = syncFile(path); err != nil {
			return result, err
		}
		if err = os.Rename(path, target); err != nil {
			return result, err
		}
		if err = syncDirectory(dir); err != nil {
			return result, err
		}
	}
	info, err := os.Stat(target)
	if err != nil {
		return result, err
	}
	return domain.Backup{ID: id, Filename: filepath.Base(target), Kind: kind, Size: info.Size(), CreatedAt: info.ModTime().UTC().Format(time.RFC3339Nano)}, nil
}

func (m *Manager) List(ctx context.Context) ([]domain.Backup, error) {
	dir, err := m.directory()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Backup, 0, len(entries))
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".sqlite" && ext != ".llmgwb" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ext)
		if !validID.MatchString(id) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		kind := "local"
		if ext == ".llmgwb" {
			kind = "portable"
		}
		result = append(result, domain.Backup{ID: id, Filename: entry.Name(), Kind: kind, Size: info.Size(), CreatedAt: info.ModTime().UTC().Format(time.RFC3339Nano)})
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, result[i].CreatedAt)
		right, _ := time.Parse(time.RFC3339Nano, result[j].CreatedAt)
		return left.After(right)
	})
	return result, nil
}

func (m *Manager) Path(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validID.MatchString(id) {
		return "", ErrNotFound
	}
	dir, err := m.directory()
	if err != nil {
		return "", err
	}
	for _, ext := range []string{".sqlite", ".llmgwb"} {
		path := filepath.Join(dir, id+ext)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", ErrNotFound
		}
		return path, nil
	}
	return "", ErrNotFound
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, err := m.Path(ctx, id)
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (m *Manager) Prune(ctx context.Context, retentionDays int) error {
	if retentionDays < 1 {
		return errors.New("backup retention must be positive")
	}
	items, err := m.List(ctx)
	if err != nil {
		return err
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	for _, item := range items {
		created, err := time.Parse(time.RFC3339Nano, item.CreatedAt)
		if err != nil {
			return fmt.Errorf("invalid backup timestamp: %w", err)
		}
		if created.Before(cutoff) {
			if err = m.Delete(ctx, item.ID); err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".backup-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func removeSnapshot(path string) {
	os.Remove(path)
	os.Remove(path + "-journal")
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
}
