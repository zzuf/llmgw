package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"llmgw/internal/app"
	"llmgw/internal/backup"
	"llmgw/internal/domain"
)

// restoreFile deliberately bypasses app.Open: a restore must be able to replace
// a damaged current database, and must not apply a previously staged restore
// before the newly requested archive has been validated. The key loader returns
// an owned key slice, which is cleared before releasing the process lock.
func restoreFile(ctx context.Context, dataDir, source string, secretStdin bool, loadKey func(string) ([]byte, error), secretReader func(string, bool) (string, error)) error {
	if source == "" {
		return errors.New("--file is required")
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("restore source must be a regular file")
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("restore source must be a regular file")
	}
	if info.Size() > 512<<20 {
		return errors.New("backup exceeds 512 MiB limit")
	}
	reader := bufio.NewReader(f)
	header, err := reader.Peek(16)
	if err != nil {
		return backup.ErrInvalidBackup
	}
	portable := bytes.HasPrefix(header, []byte("LLMGWBP1"))
	if !portable && !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		return backup.ErrInvalidBackup
	}
	passphrase := ""
	if portable || secretStdin {
		passphrase, err = secretReader("Portable backup passphrase: ", secretStdin)
		if err != nil {
			return err
		}
	}
	if portable && (len(passphrase) < 12 || len(passphrase) > 1024) {
		return errors.New("portable backup passphrase must contain 12 to 1024 bytes")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	lock, err := app.Acquire(dataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	master, err := loadKey(dataDir)
	if err != nil {
		return err
	}
	defer clear(master)
	if len(master) != 32 {
		return errors.New("invalid master key")
	}
	manager := backup.New(nil, dataDir, master)
	defer clear(manager.MasterKey)
	if err = manager.StageUploadWithAudit(ctx, reader, passphrase, domain.Audit{ActorName: "local-cli", Action: "backup.restored", Target: filepath.Base(source), Result: "success"}); err != nil {
		return err
	}
	return backup.ApplyPending(dataDir, master)
}
