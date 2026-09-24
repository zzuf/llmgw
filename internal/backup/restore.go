package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

const pendingFilename = "pending-restore.bin"

func (m *Manager) StageRestore(ctx context.Context, id, passphrase string) error {
	return m.StageRestoreWithAudit(ctx, id, passphrase, domain.Audit{ActorName: "system", Target: id})
}

// StageRestoreWithAudit carries the requesting administrator into the restored
// audit trail, which would otherwise be replaced with the older snapshot.
func (m *Manager) StageRestoreWithAudit(ctx context.Context, id, passphrase string, audit domain.Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, err := m.Path(ctx, id)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return m.stage(ctx, f, passphrase, audit)
}

func (m *Manager) StageUpload(ctx context.Context, r io.Reader, passphrase string) error {
	return m.StageUploadWithAudit(ctx, r, passphrase, domain.Audit{ActorName: "system", Target: "upload"})
}

// StageUploadWithAudit preserves who requested an imported restoration.
func (m *Manager) StageUploadWithAudit(ctx context.Context, r io.Reader, passphrase string, audit domain.Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stage(ctx, r, passphrase, audit)
}

func (m *Manager) stage(ctx context.Context, r io.Reader, passphrase string, audit domain.Audit) error {
	if _, err := m.directory(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	archive, err := readBounded(r)
	if err != nil {
		return err
	}
	defer clear(archive)
	var snapshot, sourceMaster []byte
	if bytes.HasPrefix(archive, []byte(portableMagic)) {
		snapshot, sourceMaster, err = decodePortable(archive, passphrase)
		if err != nil {
			return err
		}
		defer clear(snapshot)
		defer clear(sourceMaster)
	} else if bytes.HasPrefix(archive, []byte("SQLite format 3\x00")) {
		snapshot = archive
		sourceMaster = m.MasterKey
	} else {
		return ErrInvalidBackup
	}
	path, err := newSnapshotFile(m.DataDir)
	if err != nil {
		return err
	}
	defer removeSnapshot(path)
	if err = os.WriteFile(path, snapshot, 0600); err != nil {
		return err
	}
	db, err := openSnapshot(path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = validateDatabase(ctx, db); err != nil {
		return err
	}
	if err = checkAuthentication(ctx, db, sourceMaster); err != nil {
		return err
	}
	if err = processSecrets(ctx, db, sourceMaster, m.MasterKey); err != nil {
		return err
	}
	// Only a trusted, authenticated original may enter the migration machinery.
	if err = migrateSnapshot(ctx, db); err != nil {
		return err
	}
	if err = writeAuthentication(ctx, db, m.MasterKey); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return err
	}
	audit.ID = cryptoutil.RandomID()
	if audit.Timestamp == "" {
		audit.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if audit.ActorName == "" {
		audit.ActorName = "system"
	}
	audit.Action = "backup.restored"
	audit.Result = "success"
	if err = (&database.Store{DB: db}).AddAudit(ctx, audit); err != nil {
		return err
	}
	// VACUUM removes free pages that might retain revoked session tokens and old
	// key ciphertexts. It also leaves a self-contained database without WAL files.
	if _, err = db.ExecContext(ctx, "VACUUM"); err != nil {
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxSnapshotSize {
		return errors.New("restored snapshot exceeds backup size limit of 512 MiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	v, err := cryptoutil.New(m.MasterKey)
	if err != nil {
		return err
	}
	staged, err := v.Encrypt(data, pendingMagic)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.DataDir, pendingFilename), append([]byte(pendingMagic), staged...))
}

// ApplyPending installs a staged restore. The caller MUST hold the exclusive
// process lock and MUST NOT have opened the main database. A failed validation
// leaves both the current database and the staged restore intact.
func ApplyPending(dataDir string, master []byte) error {
	pendingPath := filepath.Join(dataDir, pendingFilename)
	info, err := os.Lstat(pendingPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("pending restore must be a regular file")
	}
	f, err := os.Open(pendingPath)
	if err != nil {
		return err
	}
	archive, err := readBounded(f)
	f.Close()
	if err != nil {
		return err
	}
	defer clear(archive)
	if !bytes.HasPrefix(archive, []byte(pendingMagic)) {
		return ErrInvalidBackup
	}
	v, err := cryptoutil.New(master)
	if err != nil {
		return err
	}
	data, err := v.Decrypt(archive[len(pendingMagic):], pendingMagic)
	if err != nil {
		return errors.New("pending restore authentication failed")
	}
	defer clear(data)
	path, err := newSnapshotFile(dataDir)
	if err != nil {
		return err
	}
	defer removeSnapshot(path)
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := openSnapshot(path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = validateDatabase(ctx, db); err != nil {
		return err
	}
	if err = checkAuthentication(ctx, db, master); err != nil {
		return err
	}
	if err = processSecrets(ctx, db, master, nil); err != nil {
		return err
	}
	// An older binary may have staged this archive before the upgrade.
	if err = migrateSnapshot(ctx, db); err != nil {
		return err
	}
	var sessions int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions").Scan(&sessions); err != nil {
		return err
	}
	if sessions != 0 {
		return fmt.Errorf("%w: staged restore contains sessions", ErrInvalidBackup)
	}
	if err = (&database.Store{DB: db}).AddAudit(ctx, domain.Audit{ActorName: "system", Action: "backup.restore_applied", Target: "llmgw.db", Result: "success"}); err != nil {
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	if err = syncFile(path); err != nil {
		return err
	}
	mainPath := filepath.Join(dataDir, "llmgw.db")
	info, err = os.Lstat(mainPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("current database must be a regular file")
		}
		// Opening in DELETE journal mode checkpoints any surviving committed WAL
		// records before replacing the main file. The rollback snapshot includes them.
		current, err := openSnapshot(mainPath)
		if err != nil {
			return err
		}
		manager := New(current, dataDir, master)
		_, backupErr := manager.Create(ctx, "local", "")
		closeErr := current.Close()
		if closeErr != nil {
			return closeErr
		}
		if backupErr != nil {
			// A damaged original cannot be snapshotted by SQLite. Preserve every
			// byte, including recovery sidecars, before installing the good copy.
			if err = preserveDamagedDatabase(manager, mainPath); err != nil {
				return fmt.Errorf("preserve original after rollback snapshot failed (%v): %w", backupErr, err)
			}
		}
	}
	// No old SQLite sidecar may survive the atomic replacement and be replayed
	// against the restored database. The caller's process lock excludes writers.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err = os.Remove(mainPath + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = os.Rename(path, mainPath); err != nil {
		return err
	}
	if err = syncDirectory(dataDir); err != nil {
		return err
	}
	if err = os.Remove(pendingPath); err != nil {
		return err
	}
	return syncDirectory(dataDir)
}

func preserveDamagedDatabase(manager *Manager, mainPath string) (err error) {
	backups, err := manager.directory()
	if err != nil {
		return err
	}
	dir := filepath.Join(backups, cryptoutil.RandomID()+".recovery")
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		sourcePath := mainPath + suffix
		info, statErr := os.Lstat(sourcePath)
		if os.IsNotExist(statErr) && suffix != "" {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return errors.New("original database files must be regular files")
		}
		source, openErr := os.Open(sourcePath)
		if openErr != nil {
			return openErr
		}
		destination, openErr := os.OpenFile(filepath.Join(dir, "llmgw.db"+suffix), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if openErr != nil {
			source.Close()
			return openErr
		}
		_, copyErr := io.Copy(destination, source)
		source.Close()
		if copyErr == nil {
			copyErr = destination.Sync()
		}
		closeErr := destination.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	return syncDirectory(backups)
}

// migrateSnapshot operates solely on the private staging copy; the live database
// and original archive remain untouched until ApplyPending's atomic replacement.
func migrateSnapshot(ctx context.Context, db *sql.DB) error {
	if err := database.Migrate(ctx, db); err != nil {
		return err
	}
	return validateDatabase(ctx, db)
}
