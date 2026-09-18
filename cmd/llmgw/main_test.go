package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"llmgw/internal/app"
	"llmgw/internal/backup"
	"llmgw/internal/database"
	"llmgw/internal/domain"
)

func TestInvalidCLIArgumentsFailBeforeStorageOrKeychain(t *testing.T) {
	for _, args := range [][]string{
		{"restore"},
		{"admin", "reset-password"},
		{"admin", "reset-password", "--username", "   "},
		{"backup", "--passphrase-stdin"},
		{"backup", "--portable=false", "--passphrase-stdin"},
		{"backup", "--data-dir", ""},
		{"backup", "unexpected"},
		{"restore", "--passphrase", "secret-on-command-line"},
		{"admin", "reset-password", "--password", "secret-on-command-line"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			called := false
			deps := commandDependencies{
				open:       func(string) (*app.Storage, error) { called = true; return nil, errors.New("storage should not open") },
				loadKey:    func(string) ([]byte, error) { called = true; return nil, errors.New("Keychain should not load") },
				readSecret: func(string, bool) (string, error) { called = true; return "", errors.New("secret should not be read") },
			}
			full := append([]string{args[0], "--data-dir", dir}, args[1:]...)
			if args[0] == "admin" {
				full = append([]string{"admin", "reset-password", "--data-dir", dir}, args[2:]...)
			}
			if err := runWithDependencies(full, deps); err == nil {
				t.Fatal("invalid command accepted")
			}
			if called {
				t.Fatal("invalid arguments reached storage or secret handling")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("invalid command created data directory")
			}
		})
	}
}

func TestReadSecretLinePreservesWhitespaceAndBoundsBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		bad               bool
	}{
		{"newline", "  secret with spaces  \n", "  secret with spaces  ", false},
		{"crlf", "secret\r\n", "secret", false},
		{"eof", "secret", "secret", false},
		{"empty", "", "", false},
		{"first-line", "first\nsecond\n", "first", false},
		{"maximum", strings.Repeat("x", 1024) + "\r\n", strings.Repeat("x", 1024), false},
		{"too-long", strings.Repeat("x", 1025) + "\n", "", true},
		{"huge", strings.Repeat("x", 4096), "", true},
		{"multibyte", strings.Repeat("界", 342), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readSecretLine(strings.NewReader(tc.input))
			if (err != nil) != tc.bad || got != tc.want {
				t.Fatalf("result length=%d err=%v", len(got), err)
			}
		})
	}
	if _, err := readSecretLine(failingReader{}); err == nil {
		t.Fatal("input error ignored")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func cliBackupFixture(t *testing.T, portable bool) (string, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	master := bytes.Repeat([]byte{11}, 32)
	s, err := database.Open(filepath.Join(dir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := domain.Admin{Username: "restored-admin", PasswordHash: "existing-hash"}
	if err = s.CreateAdmin(context.Background(), &a, true); err != nil {
		t.Fatal(err)
	}
	m := backup.New(s.DB, dir, master)
	kind, pass := "local", ""
	if portable {
		kind, pass = "portable", "a portable recovery passphrase"
	}
	b, err := m.Create(context.Background(), kind, pass)
	if err != nil {
		t.Fatal(err)
	}
	path, err := m.Path(context.Background(), b.ID)
	if err != nil {
		t.Fatal(err)
	}
	return path, master, pass
}

func TestRestoreValidatesSourceBeforeKeychainAndLock(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "invalid.bin")
	if err := os.WriteFile(invalid, []byte("not a gateway backup"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "input.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"", filepath.Join(t.TempDir(), "missing"), t.TempDir(), invalid, fifo} {
		dir := filepath.Join(t.TempDir(), "new-data")
		called := false
		err := restoreFile(context.Background(), dir, source, false, func(string) ([]byte, error) { called = true; return nil, errors.New("unexpected Keychain") }, func(string, bool) (string, error) { called = true; return "", nil })
		if err == nil {
			t.Fatalf("invalid source accepted %q", source)
		}
		if called {
			t.Fatal("invalid source reached Keychain or prompting")
		}
		if _, err = os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("invalid source created data directory or lock")
		}
	}
}

func TestPortableRestoreToNewDirectoryUsesPassphraseStdin(t *testing.T) {
	source, _, pass := cliBackupFixture(t, true)
	dir := filepath.Join(t.TempDir(), "new-destination")
	master := bytes.Repeat([]byte{13}, 32)
	readCount := 0
	err := restoreFile(context.Background(), dir, source, true,
		func(string) ([]byte, error) {
			if _, err := os.Stat(filepath.Join(dir, "llmgw.db")); !os.IsNotExist(err) {
				t.Fatal("restore opened destination DB before loading key")
			}
			return bytes.Clone(master), nil
		},
		func(_ string, stdin bool) (string, error) {
			readCount++
			if !stdin {
				t.Fatal("--passphrase-stdin was ignored")
			}
			return readSecretLine(strings.NewReader(pass + "\r\n"))
		})
	if err != nil {
		t.Fatal(err)
	}
	if readCount != 1 {
		t.Fatal("passphrase read more than once")
	}
	s, err := database.Open(filepath.Join(dir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.AdminByUsername(context.Background(), "restored-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "pending-restore.bin")); !os.IsNotExist(err) {
		t.Fatal("successful restore retained pending file")
	}
}

func TestFailedPortableRestorePreservesCurrentAndExistingPendingData(t *testing.T) {
	source, _, _ := cliBackupFixture(t, true)
	dir := t.TempDir()
	master := bytes.Repeat([]byte{14}, 32)
	current := []byte("original damaged database must survive")
	pending := []byte("previous pending restore must not be applied")
	for name, data := range map[string][]byte{"llmgw.db": current, "pending-restore.bin": pending} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := restoreFile(context.Background(), dir, source, true, func(string) ([]byte, error) { return bytes.Clone(master), nil }, func(string, bool) (string, error) { return "incorrect but long enough passphrase", nil })
	if err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	for name, want := range map[string][]byte{"llmgw.db": current, "pending-restore.bin": pending} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("failed restore changed %s", name)
		}
	}
	lock, err := app.Acquire(dir)
	if err != nil {
		t.Fatal("failed restore retained lock", err)
	}
	lock.Close()
}

func TestPassphraseFailureDoesNotCreateTarget(t *testing.T) {
	source, _, _ := cliBackupFixture(t, true)
	for _, secretErr := range []error{errors.New("secret input unavailable"), nil} {
		dir := filepath.Join(t.TempDir(), "must-not-exist")
		err := restoreFile(context.Background(), dir, source, true, func(string) ([]byte, error) { t.Fatal("invalid passphrase reached Keychain"); return nil, nil }, func(string, bool) (string, error) { return "short", secretErr })
		if err == nil {
			t.Fatal("invalid passphrase input accepted")
		}
		if _, err = os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("passphrase error created target directory")
		}
	}
}

func TestRestoreDamagedDBUsesArchiveHeaderAndPreservesCLIActor(t *testing.T) {
	for _, portable := range []bool{false, true} {
		t.Run(map[bool]string{false: "local-misleading-extension", true: "portable-renamed"}[portable], func(t *testing.T) {
			source, sourceMaster, pass := cliBackupFixture(t, portable)
			renamed := filepath.Join(t.TempDir(), "archive.llmgwb")
			if portable {
				renamed = filepath.Join(filepath.Dir(renamed), "archive.data")
			}
			content, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(renamed, content, 0600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			damaged := []byte("damaged original database")
			if err = os.WriteFile(filepath.Join(dir, "llmgw.db"), damaged, 0600); err != nil {
				t.Fatal(err)
			}
			master := sourceMaster
			if portable {
				master = bytes.Repeat([]byte{12}, 32)
			}
			readCount := 0
			deps := commandDependencies{
				open: func(string) (*app.Storage, error) {
					t.Fatal("restore tried app.Open on the damaged database")
					return nil, nil
				},
				loadKey: func(gotDir string) ([]byte, error) {
					if gotDir != dir {
						t.Fatal("wrong destination directory")
					}
					if unexpectedLock, err := app.Acquire(dir); err == nil {
						unexpectedLock.Close()
						t.Fatal("master loaded without exclusive directory lock")
					}
					return bytes.Clone(master), nil
				},
				readSecret: func(_ string, stdin bool) (string, error) {
					readCount++
					if stdin {
						t.Fatal("stdin mode unexpectedly selected")
					}
					return pass, nil
				},
			}
			if err = runWithDependencies([]string{"restore", "--file", renamed, "--data-dir", dir}, deps); err != nil {
				t.Fatal(err)
			}
			wantRead := 0
			if portable {
				wantRead = 1
			}
			if readCount != wantRead {
				t.Fatalf("secret prompts=%d want=%d", readCount, wantRead)
			}
			s, err := database.Open(filepath.Join(dir, "llmgw.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.AdminByUsername(context.Background(), "restored-admin"); err != nil {
				t.Fatal("restored data missing", err)
			}
			var actor, target string
			if err = s.DB.QueryRow("SELECT actor_name,target FROM audit_logs WHERE action='backup.restored'").Scan(&actor, &target); err != nil {
				t.Fatal(err)
			}
			if actor != "local-cli" || target != filepath.Base(renamed) {
				t.Fatalf("CLI audit missing actor=%q target=%q", actor, target)
			}
			recoveries, err := filepath.Glob(filepath.Join(dir, "backups", "*.recovery", "llmgw.db"))
			if err != nil || len(recoveries) != 1 {
				t.Fatal("damaged original not preserved")
			}
			kept, err := os.ReadFile(recoveries[0])
			if err != nil || !bytes.Equal(kept, damaged) {
				t.Fatal("damaged original bytes changed")
			}
			lock, err := app.Acquire(dir)
			if err != nil {
				t.Fatal("restore failed to release process lock", err)
			}
			lock.Close()
		})
	}
}

func TestRestoreRespectsActiveProcessLock(t *testing.T) {
	source, _, _ := cliBackupFixture(t, false)
	dir := t.TempDir()
	lock, err := app.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	called := false
	err = restoreFile(context.Background(), dir, source, false, func(string) ([]byte, error) { called = true; return nil, nil }, func(string, bool) (string, error) { t.Fatal("local backup requested a passphrase"); return "", nil })
	if err == nil || called {
		t.Fatal("restore accessed master while service lock was held")
	}
}
