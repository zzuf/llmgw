package logging

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmgw/internal/database"
	"llmgw/internal/domain"
)

func newTestLogger(t *testing.T, settings domain.Settings) (*Logger, *sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	logger, err := New(store.DB, dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Error(err)
		}
	})
	return logger, store.DB, dir
}

func sampleRecord(id string) domain.AccessRecord {
	return domain.AccessRecord{RequestID: id, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), SourceIP: "127.0.0.1", APIKeyID: "key1", APIKeyName: "research", APIKeyTags: []string{"team"}, ModelID: "model1", ModelAlias: "public", EngineID: "engine1", EngineName: "local", UpstreamModel: "private", Endpoint: "/v1/chat/completions", Method: "POST", Status: 200, DurationMS: 100, Streaming: true, Usage: domain.Usage{InputTokens: 7, OutputTokens: 11, TotalTokens: 18}, Prompt: map[string]any{"messages": []any{map[string]any{"role": "user", "content": "a normal prompt"}}}}
}

func TestLoggerWritesRedactedJSONAndIdempotentAggregates(t *testing.T) {
	logger, db, dir := newTestLogger(t, domain.DefaultSettings())
	record := sampleRecord("request1")
	record.Prompt = map[string]any{"text": "retain conversation", "image": "data:image/png;base64,c2VjcmV0"}
	if err := logger.Record(record); err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(record); err != nil {
		t.Fatal(err)
	}
	failed := sampleRecord("request2")
	failed.Status = 500
	failed.ErrorCode = "upstream_error"
	failed.Streaming = false
	if err := logger.Record(failed); err != nil {
		t.Fatal(err)
	}
	if err := logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var requests, errors, streaming, input, output, total int
	var duration float64
	if err := db.QueryRow(`SELECT requests,errors,streaming,input_tokens,output_tokens,total_tokens,duration_ms FROM daily_stats`).Scan(&requests, &errors, &streaming, &input, &output, &total, &duration); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || errors != 1 || streaming != 1 || input != 14 || output != 22 || total != 36 || duration != 200 {
		t.Fatalf("bad aggregation %d %d %d %d %d %d %f", requests, errors, streaming, input, output, total, duration)
	}
	var details int
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_stats`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if details != 2 {
		t.Fatalf("duplicate counted: %d", details)
	}
	data, err := os.ReadFile(filepath.Join(dir, "logs", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "c2VjcmV0") || !strings.Contains(string(data), "retain conversation") {
		t.Fatalf("invalid redaction: %s", data)
	}
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	count := 0
	for scan.Scan() {
		if !json.Valid(scan.Bytes()) {
			t.Fatalf("invalid JSONL: %s", scan.Bytes())
		}
		count++
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("want 3 writes, got %d", count)
	}
	info, err := os.Stat(filepath.Join(dir, "logs", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("log mode %v", info.Mode())
	}
}

func TestLoggerRotatesCompleteJSONLinesToReadableGzip(t *testing.T) {
	settings := domain.DefaultSettings()
	settings.LogRotationBytes = 1000
	settings.LogGenerations = 3
	logger, _, dir := newTestLogger(t, settings)
	for i := 0; i < 14; i++ {
		if err := logger.Record(sampleRecord(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want active+3 generations, got %v", entries)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, "logs", entry.Name())
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var reader io.Reader = file
		if strings.HasSuffix(path, ".gz") {
			gz, err := gzip.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			reader = gz
		}
		scan := bufio.NewScanner(reader)
		count := 0
		for scan.Scan() {
			if !json.Valid(scan.Bytes()) {
				t.Fatalf("invalid JSON in %s", path)
			}
			count++
		}
		if err := scan.Err(); err != nil {
			t.Fatal(err)
		}
		file.Close()
		if count == 0 {
			t.Fatalf("empty log %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe mode for %s: %v", path, info.Mode())
		}
	}
}

func TestPruneRetainsHistoricalDailyAggregates(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	record := sampleRecord("old")
	record.Timestamp = time.Now().UTC().AddDate(0, 0, -100).Format(time.RFC3339Nano)
	if err := logger.Record(record); err != nil {
		t.Fatal(err)
	}
	if err := logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := logger.Prune(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_stats`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("old details retained: %d", n)
	}
	if err := db.QueryRow(`SELECT SUM(requests) FROM daily_stats`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("history deleted: %d", n)
	}
}

func TestConcurrentRecordAndCloseDrainAcceptedRequests(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				if logger.Record(sampleRecord(fmt.Sprintf("%d/%d", worker, i))) == nil {
					accepted.Add(1)
				}
			}
		}(worker)
	}
	wg.Wait()
	var closes sync.WaitGroup
	for i := 0; i < 3; i++ {
		closes.Add(1)
		go func() {
			defer closes.Done()
			if err := logger.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	closes.Wait()
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_stats`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 480 || n != accepted.Load() {
		t.Fatalf("lost accepted records: %d/%d", n, accepted.Load())
	}
	if logger.Record(sampleRecord("closed")) == nil {
		t.Fatal("record after shutdown accepted")
	}
}

func TestFlushHonorsCanceledContextAndLiveRotationSettings(t *testing.T) {
	logger, _, dir := newTestLogger(t, domain.DefaultSettings())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if logger.Flush(ctx) == nil {
		t.Fatal("canceled flush succeeded")
	}
	settings := domain.DefaultSettings()
	settings.LogRotationBytes = 1000
	settings.LogGenerations = 1
	if err := logger.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := logger.Record(sampleRecord(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("live settings not used: %v", entries)
	}
}

func TestFlushDeadlineStillWorksWhenProducerIsBackpressured(t *testing.T) {
	logger, db, dir := newTestLogger(t, domain.DefaultSettings())
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := logger.Record(sampleRecord("first")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		info, err := os.Stat(filepath.Join(dir, "logs", "access.log"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer did not reach database")
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 128; i++ {
		if err := logger.Record(sampleRecord(fmt.Sprintf("queued-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	submitted := make(chan struct{})
	go func() { defer close(submitted); _ = logger.Record(sampleRecord("blocked")) }()
	time.Sleep(10 * time.Millisecond)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		result <- logger.Flush(ctx)
	}()
	select {
	case err := <-result:
		if err != context.DeadlineExceeded {
			t.Errorf("want context deadline, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		conn.Close()
		<-submitted
		t.Fatal("Flush ignored context while waiting on a blocked producer")
	}
	conn.Close()
	<-submitted
}

func TestStatisticsInsertAndDailyUpdateRollbackTogether(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	_, err := db.Exec(`CREATE TRIGGER reject_aggregate BEFORE INSERT ON daily_stats BEGIN SELECT RAISE(ABORT,'reject test update'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.writeStatistics(context.Background(), sampleRecord("rollback")); err == nil {
		t.Fatal("expected aggregate failure")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_stats`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial request committed: %d", count)
	}
}

func TestRotationGenerationReductionRemovesOlderFiles(t *testing.T) {
	settings := domain.DefaultSettings()
	settings.LogRotationBytes = 1000
	settings.LogGenerations = 3
	logger, _, dir := newTestLogger(t, settings)
	for i := 0; i < 5; i++ {
		if err := logger.Record(sampleRecord(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	settings.LogGenerations = 1
	if err := logger.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(sampleRecord("reduced")); err != nil {
		t.Fatal(err)
	}
	if err := logger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("older generations survived settings reduction: %v", entries)
	}
}

func TestCloseRacingRecordDoesNotLoseAcceptedWrites(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	start := make(chan struct{})
	var writers sync.WaitGroup
	var accepted atomic.Int64
	for worker := 0; worker < 8; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			<-start
			for i := 0; i < 40; i++ {
				if logger.Record(sampleRecord(fmt.Sprintf("racing-%d-%d", worker, i))) == nil {
					accepted.Add(1)
				}
			}
		}(worker)
	}
	close(start)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	writers.Wait()
	var count int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM request_stats`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != accepted.Load() {
		t.Fatalf("lost %d accepted writes", accepted.Load()-count)
	}
}

func TestGuardMetadataSnapshotAndSeparateUsage(t *testing.T) {
	logger, db, dir := newTestLogger(t, domain.DefaultSettings())
	ctx := context.Background()
	// Hold the single DB connection so the worker cannot consume the second
	// record before its caller mutates the original slices.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := logger.Record(sampleRecord("block-writer")); err != nil {
		t.Fatal(err)
	}
	record := sampleRecord("guarded")
	record.TTFTMS, record.UpstreamTTFTMS = 900, 15
	record.GuardChecks = []domain.GuardCheck{
		{Stage: "input", SafeguardID: "guard1", SafeguardName: "Qwen safety", EngineID: "guard-engine", EngineName: "Safety engine", UpstreamModel: "Qwen3Guard-Gen", Result: "allowed", Label: "Safe", Categories: []string{"None"}, DurationMS: 20, Usage: domain.Usage{InputTokens: 100, OutputTokens: 10, TotalTokens: 110}},
		{Stage: "output", SafeguardID: "guard1", SafeguardName: "Qwen safety", Result: "rejected", Label: "Unsafe", Categories: []string{"Violent"}, Refusal: "No", DurationMS: 30, ErrorCode: "guard_rejected", Usage: domain.Usage{InputTokens: 150, OutputTokens: 20, TotalTokens: 170}},
	}
	record.Status, record.ErrorCode = 403, "guard_rejected"
	wantJSON, err := json.Marshal(record.GuardChecks)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(record); err != nil {
		t.Fatal(err)
	}
	record.GuardChecks[0].Categories[0] = "mutated"
	record.GuardChecks[1].Label = "mutated"
	record.GuardChecks[0].Usage.TotalTokens = 9999
	conn.Close()
	if err := logger.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, total, err := AccessLogs(ctx, db, "request:guarded", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("missing guarded record: %d %#v", total, rows)
	}
	gotJSON, _ := json.Marshal(rows[0].GuardChecks)
	if string(gotJSON) != string(wantJSON) || rows[0].UpstreamTTFTMS != 15 || rows[0].TTFTMS != 900 {
		t.Fatalf("guard snapshot changed or missing: %s, timings %v/%v", gotJSON, rows[0].TTFTMS, rows[0].UpstreamTTFTMS)
	}
	data, err := os.ReadFile(filepath.Join(dir, "logs", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	var stored domain.AccessRecord
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("guard generated extra client log records: %d", len(lines))
	}
	if err := json.Unmarshal([]byte(lines[1]), &stored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.GuardChecks, rows[0].GuardChecks) {
		t.Fatalf("JSONL and SQLite guard metadata differ: %#v", stored.GuardChecks)
	}
	dashboard, err := Dashboard(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if dashboard["today_requests"] != int64(2) || dashboard["input_tokens"] != int64(14) || dashboard["output_tokens"] != int64(22) || dashboard["total_tokens"] != int64(36) {
		t.Fatalf("guard calls changed generation totals: %#v", dashboard)
	}
	for _, filter := range []string{"guard:Unsafe", "guard:Qwen", "guard:rejected", "guard:Violent"} {
		_, total, err := AccessLogs(ctx, db, filter, 1, 20)
		if err != nil || total != 1 {
			t.Errorf("guard filter %q: total=%d error=%v", filter, total, err)
		}
	}
}
