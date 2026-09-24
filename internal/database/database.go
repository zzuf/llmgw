// Package database owns schema migrations and transactional configuration storage.
package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
)

var (
	ErrConflict     = errors.New("conflicting record or dependent records exist")
	ErrNotFound     = errors.New("record not found")
	ErrLastAdmin    = errors.New("the final administrator cannot be deleted")
	ErrAlreadySetup = errors.New("an administrator already exists")
)

const SchemaVersion = 2

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	DB   *sql.DB
	Path string
}

// Open creates a private database and applies supported numbered migrations.
// A single connection serializes short writes; every query closes its rows before
// querying related records. The DSN also reapplies pragmas if a connection expires.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	dsn := path
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = absolute
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
			return nil, errors.New("database must be a regular file")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "file", Path: path}
		dsn = u.String()
	}
	dsn += "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{DB: db, Path: path}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.initializeSettings(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.Chmod(path+suffix, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
				db.Close()
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// Migrate upgrades an already-open, trusted database and initializes new settings.
// Callers restoring external databases must validate their original schema and
// authenticate all secrets before invoking this function.
func Migrate(ctx context.Context, db *sql.DB) error {
	s := &Store{DB: db}
	if err := s.migrate(ctx); err != nil {
		return err
	}
	return s.initializeSettings(ctx)
}

// ReferenceSchema builds an in-memory schema exclusively from embedded migrations.
// It never reads definitions from a backup and supports historical schema checks.
func ReferenceSchema(ctx context.Context, version int) (*sql.DB, error) {
	if version < 1 || version > SchemaVersion {
		return nil, errors.New("unsupported reference schema version")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := (&Store{DB: db}).migrateTo(ctx, version); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (s *Store) migrate(ctx context.Context) error {
	return s.migrateTo(ctx, SchemaVersion)
}

func (s *Store) migrateTo(ctx context.Context, targetVersion int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version > targetVersion {
		return fmt.Errorf("database schema %d is newer than supported version %d", version, targetVersion)
	}
	for next := version + 1; next <= targetVersion; next++ {
		contents, err := migrations.ReadFile(fmt.Sprintf("migrations/%03d_initial.sql", next))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(contents)); err != nil {
			return fmt.Errorf("migration %d: %w", next, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", next, now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func ensureID(id *string) error {
	if *id != "" {
		return nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	*id = hex.EncodeToString(b[:])
	return nil
}

func dbError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code()&255 == 19 {
		return fmt.Errorf("%w: %s", ErrConflict, sqliteErr.Error())
	}
	return err
}

func changed(result sql.Result, err error) error {
	if err != nil {
		return dbError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(...any) error }
type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
