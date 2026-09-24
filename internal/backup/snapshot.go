package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
)

const authSchema = `CREATE TABLE llmgw_backup_auth (id INTEGER PRIMARY KEY CHECK(id=1), cipher BLOB NOT NULL)`
const authPurpose = "backup-key-verification:v1"
const authPlaintext = "llmgw authenticated snapshot version 1"

func openSnapshot(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs}
	db, err := sql.Open("sqlite", u.String()+"?mode=rw&_pragma=trusted_schema(0)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(DELETE)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func newSnapshotFile(dir string) (string, error) {
	f, err := os.CreateTemp(dir, ".snapshot-*.sqlite")
	if err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (m *Manager) snapshot(ctx context.Context) (path string, err error) {
	path, err = newSnapshotFile(m.DataDir)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			removeSnapshot(path)
		}
	}()
	if _, err = m.DB.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return path, fmt.Errorf("snapshot database: %w", err)
	}
	db, err := openSnapshot(path)
	if err != nil {
		return path, err
	}
	defer db.Close()
	if err = validateDatabase(ctx, db); err != nil {
		return path, err
	}
	if err = processSecrets(ctx, db, m.MasterKey, nil); err != nil {
		return path, err
	}
	if err = writeAuthentication(ctx, db, m.MasterKey); err != nil {
		return path, err
	}
	return path, db.Close()
}

// schemaDefinition compares the restored schema with one produced by trusted
// embedded migrations for its exact original version. This rejects triggers, virtual
// tables, altered constraints and schema masquerading, not merely an attacker-
// controlled schema_migrations version number.
func schemaDefinition(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var kind, name, definition string
		if err = rows.Scan(&kind, &name, &definition); err != nil {
			return nil, err
		}
		result[kind+":"+name] = strings.Join(strings.Fields(definition), " ")
	}
	return result, rows.Err()
}

func validateDatabase(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return ErrInvalidBackup
	}
	var messages []string
	for rows.Next() {
		var result string
		if err = rows.Scan(&result); err != nil {
			rows.Close()
			return ErrInvalidBackup
		}
		messages = append(messages, result)
		if len(messages) > 1 {
			break
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(messages) != 1 || messages[0] != "ok" {
		return fmt.Errorf("%w: SQLite integrity check failed", ErrInvalidBackup)
	}
	var version, count, minimum int
	if err = db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0),COUNT(*),COALESCE(MIN(version),0) FROM schema_migrations").Scan(&version, &count, &minimum); err != nil || version < 1 || version > database.SchemaVersion || count != version || minimum != 1 {
		return fmt.Errorf("%w: schema version is not supported", ErrInvalidBackup)
	}
	actual, err := schemaDefinition(ctx, db)
	if err != nil {
		return ErrInvalidBackup
	}
	if definition, ok := actual["table:llmgw_backup_auth"]; ok {
		if definition != strings.Join(strings.Fields(authSchema), " ") {
			return fmt.Errorf("%w: invalid authentication schema", ErrInvalidBackup)
		}
		delete(actual, "table:llmgw_backup_auth")
	}
	reference, err := database.ReferenceSchema(ctx, version)
	if err != nil {
		return fmt.Errorf("load reference schema: %w", err)
	}
	expected, err := schemaDefinition(ctx, reference)
	reference.Close()
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("%w: unexpected database schema", ErrInvalidBackup)
	}
	for name, definition := range expected {
		if actual[name] != definition {
			return fmt.Errorf("%w: schema mismatch for %s", ErrInvalidBackup, name)
		}
	}
	rows, err = db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return ErrInvalidBackup
	}
	broken := rows.Next()
	err = rows.Err()
	rows.Close()
	if broken || err != nil {
		return fmt.Errorf("%w: foreign key integrity check failed", ErrInvalidBackup)
	}
	return nil
}

func writeAuthentication(ctx context.Context, db *sql.DB, master []byte) error {
	v, err := cryptoutil.New(master)
	if err != nil {
		return err
	}
	ciphertext, err := v.Encrypt([]byte(authPlaintext), authPurpose)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, strings.Replace(authSchema, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO llmgw_backup_auth(id,cipher) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET cipher=excluded.cipher", ciphertext)
	return err
}

func checkAuthentication(ctx context.Context, db *sql.DB, master []byte) error {
	v, err := cryptoutil.New(master)
	if err != nil {
		return err
	}
	var ciphertext []byte
	if err = db.QueryRowContext(ctx, "SELECT cipher FROM llmgw_backup_auth WHERE id=1").Scan(&ciphertext); err != nil {
		return fmt.Errorf("%w: missing snapshot authentication", ErrInvalidBackup)
	}
	plaintext, err := v.Decrypt(ciphertext, authPurpose)
	defer clear(plaintext)
	if err != nil || !bytes.Equal(plaintext, []byte(authPlaintext)) {
		return errors.New("backup does not match this master key or is damaged")
	}
	return nil
}

func processSecrets(ctx context.Context, db *sql.DB, sourceMaster, destinationMaster []byte) error {
	source, err := cryptoutil.New(sourceMaster)
	if err != nil {
		return err
	}
	var destination *cryptoutil.Vault
	if destinationMaster != nil {
		destination, err = cryptoutil.New(destinationMaster)
		if err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []struct{ name, purpose string }{{"engines", "engine:"}, {"api_keys", "api-key:"}} {
		query := "SELECT id,secret_cipher,'api-key' FROM " + table.name
		if table.name == "engines" {
			query = "SELECT id,secret_cipher,auth_type FROM engines"
		}
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		type record struct {
			id         string
			ciphertext []byte
			authType   string
		}
		records := []record{}
		for rows.Next() {
			var r record
			if err = rows.Scan(&r.id, &r.ciphertext, &r.authType); err != nil {
				rows.Close()
				return err
			}
			records = append(records, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, r := range records {
			if table.name == "engines" {
				switch r.authType {
				case "none", "bearer", "x-api-key":
				default:
					return fmt.Errorf("%w: unsupported engine authentication type", ErrInvalidBackup)
				}
			}
			if len(r.ciphertext) == 0 {
				if table.name == "engines" && r.authType == "none" {
					continue
				}
				return fmt.Errorf("%w: %s credential is missing", ErrInvalidBackup, table.name)
			}
			plaintext, err := source.Decrypt(r.ciphertext, table.purpose+r.id)
			if err != nil {
				return fmt.Errorf("authenticate %s credential: %w", table.name, err)
			}
			if destination != nil {
				rewrapped, encErr := destination.Encrypt(plaintext, table.purpose+r.id)
				clear(plaintext)
				if encErr != nil {
					return encErr
				}
				if _, err = tx.ExecContext(ctx, "UPDATE "+table.name+" SET secret_cipher=? WHERE id=?", rewrapped, r.id); err != nil {
					return err
				}
			} else {
				clear(plaintext)
			}
		}
	}
	return tx.Commit()
}
