package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"llmgw/internal/backup"
	"llmgw/internal/config"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/gateway"
	"llmgw/internal/keychain"
	"llmgw/internal/logging"
)

type Storage struct {
	Store     *database.Store
	Vault     *cryptoutil.Vault
	Backups   *backup.Manager
	MasterKey []byte
	Lock      *Lock
}

func Open(dataDir string) (*Storage, error) {
	path, e := filepath.Abs(dataDir)
	if e != nil {
		return nil, e
	}
	lock, e := Acquire(path)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	var master []byte
	if _, e = os.Stat(filepath.Join(path, "llmgw.db")); e == nil {
		master, e = keychain.Load(path)
	} else if os.IsNotExist(e) {
		master, e = keychain.LoadOrCreate(path)
	}
	if e != nil {
		return nil, e
	}
	if e = backup.ApplyPending(path, master); e != nil {
		return nil, e
	}
	store, e := database.Open(filepath.Join(path, "llmgw.db"))
	if e != nil {
		return nil, e
	}
	vault, e := cryptoutil.New(master)
	if e != nil {
		store.Close()
		return nil, e
	}
	success = true
	return &Storage{store, vault, backup.New(store.DB, path, master), master, lock}, nil
}
func (s *Storage) Close() error { defer s.Lock.Close(); return s.Store.Close() }

type Runtime struct {
	storage       *Storage
	logger        *logging.Logger
	gateway       *gateway.Server
	mu            sync.Mutex
	servers       []*http.Server
	current       *http.Server
	address       string
	ctx           context.Context
	requestCancel context.CancelFunc
	stopping      bool
	shutdownDone  chan struct{}
	shutdownErr   error
	serveErrors   chan error
	handlers      sync.WaitGroup
	wg            sync.WaitGroup
}

// The signal/background lifetime is distinct from active HTTP requests. Requests
// retain their own deadlines and can finish during the graceful shutdown window.
func newRuntime(parent context.Context, storage *Storage, logger *logging.Logger, settings domain.Settings) *Runtime {
	requests, cancel := context.WithCancel(context.WithoutCancel(parent))
	rt := &Runtime{storage: storage, logger: logger, ctx: requests, requestCancel: cancel, address: settings.ListenAddress, shutdownDone: make(chan struct{}), serveErrors: make(chan error, 1)}
	rt.gateway = gateway.New(storage.Store, storage.Vault, logger, storage.Backups)
	rt.gateway.ApplySettings = rt.apply
	return rt
}

func Run(ctx context.Context, dataDir, initialListen string) error {
	newDB := false
	if _, e := os.Stat(filepath.Join(dataDir, "llmgw.db")); os.IsNotExist(e) {
		newDB = true
	}
	storage, e := Open(dataDir)
	if e != nil {
		return e
	}
	defer storage.Close()
	settings, e := storage.Store.Settings(ctx)
	if e != nil {
		return e
	}
	if newDB && initialListen != "" {
		settings.ListenAddress = initialListen
		if e = config.Validate(settings); e != nil {
			return e
		}
		if e = storage.Store.SaveSettings(ctx, settings); e != nil {
			return e
		}
	}
	logger, e := logging.New(storage.Store.DB, dataDir, settings)
	if e != nil {
		return e
	}
	defer func() {
		if e := logger.Close(); e != nil {
			slog.Error("log drain failed", "error", e)
		}
	}()
	rt := newRuntime(ctx, storage, logger, settings)
	defer rt.requestCancel()
	listener, e := net.Listen("tcp", settings.ListenAddress)
	if e != nil {
		return e
	}
	slog.Info("gateway listening", "address", settings.ListenAddress, "data_dir", dataDir)
	return rt.run(ctx, listener)
}

func (rt *Runtime) run(ctx context.Context, listener net.Listener) error {
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	rt.mu.Lock()
	if rt.stopping {
		rt.mu.Unlock()
		listener.Close()
		return errors.New("gateway is shutting down")
	}
	rt.launch(listener)
	rt.mu.Unlock()
	rt.wg.Add(1)
	go func() { defer rt.wg.Done(); rt.background(life) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-rt.serveErrors:
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	shutdownErr := rt.shutdown(shutdownCtx)
	rt.wg.Wait()
	return errors.Join(serveErr, shutdownErr)
}

// shutdown first closes listeners, then drains handlers. Only expiration of the
// grace window cancels active requests and closes their connections.
func (rt *Runtime) shutdown(ctx context.Context) error {
	rt.mu.Lock()
	if rt.stopping {
		done := rt.shutdownDone
		rt.mu.Unlock()
		select {
		case <-done:
			return rt.shutdownErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	rt.stopping = true
	servers := append([]*http.Server(nil), rt.servers...)
	rt.mu.Unlock()
	var wg sync.WaitGroup
	failures := make(chan error, len(servers))
	for _, server := range servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if e := s.Shutdown(ctx); e != nil {
				rt.requestCancel()
				_ = s.Close()
				failures <- e
			}
			rt.forget(s)
		}(server)
	}
	wg.Wait()
	rt.requestCancel()
	// Close does not itself wait for handler defers; usage must be queued before
	// the caller drains its logger and closes SQLite.
	rt.handlers.Wait()
	close(failures)
	for err := range failures {
		rt.shutdownErr = errors.Join(rt.shutdownErr, err)
	}
	close(rt.shutdownDone)
	return rt.shutdownErr
}

// launch is called with rt.mu held so admission, settings and shutdown cannot
// race a newly bound listener into service after the shutdown snapshot.
func (rt *Runtime) launch(listener net.Listener) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		if rt.stopping {
			rt.mu.Unlock()
			http.Error(w, "Gateway is shutting down", http.StatusServiceUnavailable)
			return
		}
		rt.handlers.Add(1)
		rt.mu.Unlock()
		defer rt.handlers.Done()
		rt.gateway.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, BaseContext: func(net.Listener) context.Context { return rt.ctx }}
	rt.servers = append(rt.servers, server)
	rt.current = server
	go func() {
		if e := server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
			slog.Error("listener failed", "error", e)
			select {
			case rt.serveErrors <- e:
			default:
			}
		}
	}()
}

func (rt *Runtime) forget(server *http.Server) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if index := slices.Index(rt.servers, server); index >= 0 {
		rt.servers = slices.Delete(rt.servers, index, index+1)
	}
	if rt.current == server {
		rt.current = nil
	}
}

func (rt *Runtime) retire(server *http.Server, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
	}
	rt.forget(server)
}

func (rt *Runtime) apply(ctx context.Context, s domain.Settings) error {
	if err := config.Validate(s); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.stopping {
		return errors.New("gateway is shutting down")
	}
	previous, e := rt.storage.Store.Settings(ctx)
	if e != nil {
		return e
	}
	var listener net.Listener
	if s.ListenAddress != rt.address {
		listener, e = net.Listen("tcp", s.ListenAddress)
		if e != nil {
			return e
		}
	}
	if e = rt.storage.Store.SaveSettings(ctx, s); e != nil {
		if listener != nil {
			listener.Close()
		}
		return e
	}
	if e = rt.logger.UpdateSettings(s); e != nil {
		if listener != nil {
			listener.Close()
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return errors.Join(e, rt.storage.Store.SaveSettings(rollbackCtx, previous))
	}
	if listener != nil {
		old := rt.current
		rt.address = s.ListenAddress
		rt.launch(listener)
		if old != nil {
			go rt.retire(old, time.Duration(previous.RequestTimeoutSeconds+30)*time.Second)
		}
	}
	return nil
}
func (rt *Runtime) background(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastHealth := time.Time{}
	nextMaintenance := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			settings, e := rt.storage.Store.Settings(ctx)
			if e != nil {
				continue
			}
			if lastHealth.IsZero() || !now.Before(lastHealth.Add(time.Duration(settings.HealthIntervalSeconds)*time.Second)) {
				engines, e := rt.storage.Store.ListEngines(ctx)
				if e == nil {
					for _, en := range engines {
						if en.Enabled {
							if _, e = rt.gateway.CheckEngine(ctx, en.ID); e != nil && ctx.Err() == nil {
								slog.Warn("health state save failed", "engine_id", en.ID)
							}
						}
					}
				}
				lastHealth = now
			}
			if !now.Before(nextMaintenance) {
				if settings.AutoBackupEnabled {
					items, e := rt.storage.Backups.List(ctx)
					if e == nil {
						recent := false
						for _, b := range items {
							created, _ := time.Parse(time.RFC3339Nano, b.CreatedAt)
							if b.Kind == "local" && now.Sub(created) < 24*time.Hour {
								recent = true
								break
							}
						}
						if !recent {
							b, e := rt.storage.Backups.Create(ctx, "local", "")
							if e != nil {
								slog.Error("automatic backup failed")
							} else {
								_ = rt.storage.Store.AddAudit(ctx, domain.Audit{ActorName: "system", Action: "backup.created", Target: b.ID, Result: "success"})
							}
						}
					}
				}
				if e := rt.storage.Backups.Prune(ctx, settings.BackupRetentionDays); e != nil {
					slog.Warn("backup retention failed")
				}
				if e := rt.logger.Prune(ctx, settings.StatisticsRetentionDays); e != nil {
					slog.Warn("statistics retention failed")
				}
				_, _ = rt.storage.Store.DB.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", now.UTC().Format(time.RFC3339Nano))
				nextMaintenance = now.Add(time.Minute)
			}
		}
	}
}
