package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"llmgw/internal/app"
	"llmgw/internal/config"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/domain"
	"llmgw/internal/keychain"
	"llmgw/internal/service"
)

var version = "0.1.0"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "llmgw:", e)
		os.Exit(1)
	}
}
func usage() {
	fmt.Print(`LLM Gateway

  llmgw serve [--data-dir PATH] [--listen ADDRESS]
  llmgw version
  llmgw admin reset-password --username NAME [--password-stdin] [--data-dir PATH]
  llmgw backup [--portable] [--passphrase-stdin] [--data-dir PATH]
  llmgw restore --file PATH [--passphrase-stdin] [--data-dir PATH]
  llmgw install-service [--data-dir PATH]
  llmgw uninstall-service | start | stop | status

Data directory defaults to ~/Library/Application Support/LLMGateway;
LLMGW_DATA_DIR overrides it. LLMGW_LISTEN supplies the first-run listener default.
Database settings take precedence after first run. CLI backup/restore/password
reset require the running service to be stopped. Secrets never use command arguments.
`)
}

type commandDependencies struct {
	open       func(string) (*app.Storage, error)
	loadKey    func(string) ([]byte, error)
	readSecret func(string, bool) (string, error)
}

func run(args []string) error {
	return runWithDependencies(args, commandDependencies{open: app.Open, loadKey: keychain.LoadOrCreate, readSecret: readSecret})
}

func runWithDependencies(args []string, deps commandDependencies) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	cmd := args[0]
	args = args[1:]
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		usage()
		return nil
	}
	if cmd == "version" {
		fmt.Println("llmgw", version)
		return nil
	}
	if cmd == "admin" {
		if len(args) == 0 || args[0] != "reset-password" {
			return errors.New("use admin reset-password --username NAME")
		}
		cmd = "reset-password"
		args = args[1:]
	}
	flags := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dataDir := flags.String("data-dir", config.DataDir(), "data directory")
	var listen, username, file string
	var portable, secretStdin bool
	switch cmd {
	case "serve":
		flags.StringVar(&listen, "listen", os.Getenv("LLMGW_LISTEN"), "initial listen address (persisted DB settings take precedence)")
	case "reset-password":
		flags.StringVar(&username, "username", "", "administrator username")
		flags.BoolVar(&secretStdin, "password-stdin", false, "read password from stdin")
	case "backup":
		flags.BoolVar(&portable, "portable", false, "create passphrase-encrypted portable backup")
		flags.BoolVar(&secretStdin, "passphrase-stdin", false, "read passphrase from stdin")
	case "restore":
		flags.StringVar(&file, "file", "", "backup file")
		flags.BoolVar(&secretStdin, "passphrase-stdin", false, "read passphrase from stdin")
	case "install-service", "uninstall-service", "start", "stop", "status":
	default:
		return errors.New("unknown command; use llmgw help")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *dataDir == "" {
		return errors.New("--data-dir must not be empty")
	}
	if cmd == "reset-password" && strings.TrimSpace(username) == "" {
		return errors.New("--username is required")
	}
	if cmd == "backup" && secretStdin && !portable {
		return errors.New("--passphrase-stdin requires --portable for backup")
	}
	abs, e := filepath.Abs(*dataDir)
	if e != nil {
		return e
	}
	*dataDir = abs
	switch cmd {
	case "restore":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if e := restoreFile(ctx, *dataDir, file, secretStdin, deps.loadKey, deps.readSecret); e != nil {
			return e
		}
		fmt.Println("Backup restored. Start the service to use the restored database.")
		return nil
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return app.Run(ctx, *dataDir, listen)
	case "install-service":
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		return service.Install(exe, *dataDir)
	case "uninstall-service":
		return service.Uninstall()
	case "start":
		return service.Start()
	case "stop":
		return service.Stop()
	case "status":
		out, e := service.Status()
		fmt.Print(out)
		return e
	}
	// Maintenance commands take the same exclusive process lock as serve.
	storage, e := deps.open(*dataDir)
	if e != nil {
		return e
	}
	defer storage.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	switch cmd {
	case "reset-password":
		a, e := storage.Store.AdminByUsername(ctx, username)
		if e != nil {
			return errors.New("administrator not found")
		}
		password, e := deps.readSecret("New password: ", secretStdin)
		if e != nil {
			return e
		}
		if len(password) < 12 {
			return errors.New("password must be at least 12 characters")
		}
		hash, e := cryptoutil.HashPassword(password)
		if e != nil {
			return e
		}
		if e = storage.Store.ChangePassword(ctx, a.ID, hash); e != nil {
			return e
		}
		if e = storage.Store.AddAudit(ctx, domain.Audit{ActorName: "local-cli", Action: "admin.password_changed", Target: a.ID, Result: "success"}); e != nil {
			return e
		}
		fmt.Println("Password changed; existing sessions revoked.")
		return nil
	case "backup":
		kind := "local"
		passphrase := ""
		if portable {
			kind = "portable"
			passphrase, e = deps.readSecret("Portable backup passphrase: ", secretStdin)
			if e != nil {
				return e
			}
		}
		b, e := storage.Backups.Create(ctx, kind, passphrase)
		if e != nil {
			return e
		}
		if e = storage.Store.AddAudit(ctx, domain.Audit{ActorName: "local-cli", Action: "backup.created", Target: b.ID, Result: "success"}); e != nil {
			return e
		}
		path, e := storage.Backups.Path(ctx, b.ID)
		if e != nil {
			return e
		}
		fmt.Println(path)
		return nil
	}
	return nil
}
func readSecret(prompt string, stdin bool) (string, error) {
	if stdin {
		return readSecretLine(os.Stdin)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("use --password-stdin or --passphrase-stdin when no terminal is available")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	defer clear(b)
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", e
	}
	if len(b) > 1024 {
		return "", errors.New("secret exceeds 1024 bytes")
	}
	return string(b), nil
}

func readSecretLine(input io.Reader) (string, error) {
	r := bufio.NewReader(io.LimitReader(input, 1026))
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) > 1024 {
		return "", errors.New("secret exceeds 1024 bytes")
	}
	return line, nil
}
