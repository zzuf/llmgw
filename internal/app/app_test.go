package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"llmgw/internal/backup"
	"llmgw/internal/cryptoutil"
	"llmgw/internal/database"
	"llmgw/internal/domain"
	"llmgw/internal/logging"
)

func runtimeFixture(t *testing.T) (*Runtime, net.Listener, domain.Settings) {
	t.Helper()
	dir := t.TempDir()
	store, err := database.Open(filepath.Join(dir, "llmgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x37}, 32)
	vault, err := cryptoutil.New(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	settings := domain.DefaultSettings()
	settings.ListenAddress = listener.Addr().String()
	settings.AutoBackupEnabled = false
	if err := store.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	logger, err := logging.New(store.DB, dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	storage := &Storage{Store: store, Vault: vault, Backups: backup.New(store.DB, dir, key), MasterKey: key}
	rt := newRuntime(context.Background(), storage, logger, settings)
	t.Cleanup(func() {
		listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rt.shutdown(ctx)
		if err := logger.Close(); err != nil {
			t.Error(err)
		}
		store.Close()
	})
	return rt, listener, settings
}

func launchFixture(rt *Runtime, listener net.Listener) {
	rt.mu.Lock()
	rt.launch(listener)
	rt.mu.Unlock()
}

func readHealth(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("health returned %d", response.StatusCode)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func TestListenerBindFailurePreservesStoredSettingsAndOldListener(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	launchFixture(rt, listener)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	proposed := settings
	proposed.ListenAddress = occupied.Addr().String()
	proposed.HealthIntervalSeconds = 7
	if err := rt.apply(context.Background(), proposed); err == nil {
		t.Fatal("occupied listener address accepted")
	}
	actual, err := rt.storage.Store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual != settings {
		t.Fatalf("settings changed after bind failure: %+v", actual)
	}
	readHealth(t, settings.ListenAddress)
}

func TestFailedLoggerUpdateRollsBackSettingsAndNewListener(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	launchFixture(rt, listener)
	if err := rt.logger.Close(); err != nil {
		t.Fatal(err)
	}
	proposed := settings
	proposed.ListenAddress = freeAddress(t)
	proposed.HealthIntervalSeconds = 7
	if err := rt.apply(context.Background(), proposed); !errors.Is(err, logging.ErrClosed) {
		t.Fatalf("want logger failure, got %v", err)
	}
	actual, err := rt.storage.Store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual != settings {
		t.Fatalf("settings not rolled back: %+v", actual)
	}
	probe, err := net.Listen("tcp", proposed.ListenAddress)
	if err != nil {
		t.Fatalf("failed update leaked listener: %v", err)
	}
	probe.Close()
	readHealth(t, settings.ListenAddress)
}

func TestApplyRejectsInvalidSettingsAndChangesDuringShutdown(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	launchFixture(rt, listener)
	invalid := settings
	invalid.RequestTimeoutSeconds = 0
	if err := rt.apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid settings accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rt.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	changed := settings
	changed.ListenAddress = freeAddress(t)
	if err := rt.apply(context.Background(), changed); err == nil {
		t.Fatal("listener started during shutdown")
	}
	actual, err := rt.storage.Store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual != settings {
		t.Fatal("shutdown or invalid update changed settings")
	}
}

func TestRepeatedListenerChangesDiscardRetiredServers(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	launchFixture(rt, listener)
	for i := 0; i < 5; i++ {
		settings.ListenAddress = freeAddress(t)
		if err := rt.apply(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
		readHealth(t, settings.ListenAddress)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rt.mu.Lock()
		count := len(rt.servers)
		rt.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retired servers retained: %d", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func addStreamingModel(t *testing.T, rt *Runtime, upstreamURL string) {
	t.Helper()
	ctx := context.Background()
	engine := domain.Engine{ID: "engine", Name: "mock", BaseURL: upstreamURL, Type: "generic", AuthType: "none", Enabled: true}
	if err := rt.storage.Store.SaveEngine(ctx, &engine); err != nil {
		t.Fatal(err)
	}
	capabilities := map[string]bool{"chat_completions": true, "streaming": true}
	if err := rt.storage.Store.SyncModels(ctx, engine.ID, []domain.UpstreamModel{{EngineID: engine.ID, UpstreamID: "private", Available: true, Capabilities: capabilities}}); err != nil {
		t.Fatal(err)
	}
	model := domain.Model{ID: "model", Alias: "public", EngineID: engine.ID, UpstreamModelID: "private", Published: true, Capabilities: capabilities, AllowedIPs: []string{}}
	if err := rt.storage.Store.SaveModel(ctx, &model); err != nil {
		t.Fatal(err)
	}
}

func TestSignalShutdownLetsExistingStreamFinishAndDrainsLog(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	release := make(chan struct{})
	started := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			io.WriteString(w, `{"data":[{"id":"private"}]}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"private\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
			close(canceled)
			return
		case <-release:
		}
		io.WriteString(w, "data: {\"model\":\"private\",\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	addStreamingModel(t, rt, upstream.URL)
	signal, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- rt.run(signal, listener) }()
	response, err := http.Post("http://"+settings.ListenAddress+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"public","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "first") {
		t.Fatalf("first SSE event missing: %s", scanner.Text())
	}
	<-started
	cancel()
	select {
	case <-canceled:
		t.Fatal("signal canceled upstream before graceful drain")
	case <-finished:
		t.Fatal("shutdown finished before active stream")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	all := scanner.Text()
	for scanner.Scan() {
		all += scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all, "[DONE]") {
		t.Fatalf("stream was truncated: %s", all)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown failed to finish")
	}
	if err := rt.logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var requests, tokens int
	if err := rt.storage.Store.DB.QueryRow(`SELECT SUM(requests),SUM(total_tokens) FROM daily_stats WHERE model_id='model'`).Scan(&requests, &tokens); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || tokens != 5 {
		t.Fatalf("shutdown lost usage: %d requests, %d tokens", requests, tokens)
	}
}

func TestHealthIntervalChangeReschedulesNextProbe(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	defer listener.Close()
	settings.HealthIntervalSeconds = 60
	if err := rt.apply(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	probes := make(chan struct{}, 10)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case probes <- struct{}{}:
		default:
		}
		io.WriteString(w, `{"data":[{"id":"private"}]}`)
	}))
	defer upstream.Close()
	addStreamingModel(t, rt, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); rt.background(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-probes:
	case <-time.After(2 * time.Second):
		t.Fatal("initial health probe missing")
	}
	settings.HealthIntervalSeconds = 1
	if err := rt.apply(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probes:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("new health interval waited for previous 60-second deadline")
	}
}

func TestShutdownDeadlineCancelsUpstreamBeforeReturning(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"private\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	addStreamingModel(t, rt, upstream.URL)
	launchFixture(rt, listener)
	response, err := http.Post("http://"+settings.ListenAddress+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"public","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rt.shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected grace deadline, got %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream survived forced shutdown")
	}
	if err := rt.logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var requests, failures int
	if err := rt.storage.Store.DB.QueryRow(`SELECT SUM(requests),SUM(errors) FROM daily_stats WHERE model_id='model'`).Scan(&requests, &failures); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || failures != 1 {
		t.Fatalf("unfinished handler lost error statistics: %d/%d", requests, failures)
	}
}

func TestListenerReplacementDrainsOldStreamWhileNewAddressServes(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"model\":\"private\",\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			io.WriteString(w, "data: [DONE]\n\n")
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	addStreamingModel(t, rt, upstream.URL)
	launchFixture(rt, listener)
	response, err := http.Post("http://"+settings.ListenAddress+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"public","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	settings.ListenAddress = freeAddress(t)
	settings.RequestTimeoutSeconds = 1
	if err := rt.apply(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	readHealth(t, settings.ListenAddress)
	close(release)
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("[DONE]")) {
		t.Fatalf("old stream truncated after replacing listener: %s", data)
	}
}

func TestSettingsDatabaseFailureReleasesNewListener(t *testing.T) {
	rt, listener, settings := runtimeFixture(t)
	launchFixture(rt, listener)
	_, err := rt.storage.Store.DB.Exec(`CREATE TRIGGER reject_settings BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT,'reject test update'); END`)
	if err != nil {
		t.Fatal(err)
	}
	proposed := settings
	proposed.ListenAddress = freeAddress(t)
	if err := rt.apply(context.Background(), proposed); err == nil {
		t.Fatal("failed transaction accepted")
	}
	probe, err := net.Listen("tcp", proposed.ListenAddress)
	if err != nil {
		t.Fatalf("failed transaction leaked bound socket: %v", err)
	}
	probe.Close()
	actual, err := rt.storage.Store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual != settings {
		t.Fatal("settings changed after failed transaction")
	}
	readHealth(t, settings.ListenAddress)
}
