// Package logging persists prompt-redacted JSONL records and durable usage statistics.
package logging

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"llmgw/internal/domain"
)

var ErrClosed = errors.New("access logger is closed")

type queuedWrite struct {
	record  *domain.AccessRecord
	barrier chan error
}

// Logger has one writer and a bounded queue. Call Record after forwarding the
// response: a full queue deliberately waits rather than losing usage records.
type Logger struct {
	db         *sql.DB
	path       string
	queue      chan queuedWrite
	done       chan struct{}
	gate       chan struct{} // Serializes submission/close, with cancellable Flush acquisition.
	closed     bool
	settings   atomic.Value
	errMu      sync.Mutex
	firstError error
	file       *os.File // Owned exclusively by the writer after New returns.
	size       int64
}

func normalizeSettings(settings domain.Settings) (domain.Settings, error) {
	if settings.LogRotationBytes < 0 || settings.LogGenerations < 0 {
		return settings, errors.New("log rotation size and generations cannot be negative")
	}
	defaults := domain.DefaultSettings()
	if settings.LogRotationBytes == 0 {
		settings.LogRotationBytes = defaults.LogRotationBytes
	}
	if settings.LogGenerations == 0 {
		settings.LogGenerations = defaults.LogGenerations
	}
	if settings.StatisticsRetentionDays <= 0 {
		settings.StatisticsRetentionDays = defaults.StatisticsRetentionDays
	}
	return settings, nil
}

func New(db *sql.DB, dataDir string, settings domain.Settings) (*Logger, error) {
	if db == nil {
		return nil, errors.New("access logger requires a database")
	}
	settings, err := normalizeSettings(settings)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	logger := &Logger{db: db, path: filepath.Join(dir, "access.log"), queue: make(chan queuedWrite, 128), done: make(chan struct{}), gate: make(chan struct{}, 1)}
	logger.gate <- struct{}{}
	logger.settings.Store(settings)
	if err := logger.open(); err != nil {
		return nil, err
	}
	go logger.run()
	return logger, nil
}

func (l *Logger) UpdateSettings(settings domain.Settings) error {
	settings, err := normalizeSettings(settings)
	if err != nil {
		return err
	}
	<-l.gate
	defer func() { l.gate <- struct{}{} }()
	if l.closed {
		return ErrClosed
	}
	l.settings.Store(settings)
	return nil
}

// Record takes a redacted snapshot before queuing. A successful call guarantees
// the record will be processed before Close returns; Flush/Close report I/O errors.
func (l *Logger) Record(record domain.AccessRecord) error {
	record.Prompt = RedactPrompt(record.Prompt)
	record.APIKeyTags = append([]string{}, record.APIKeyTags...)
	record.GuardChecks = append([]domain.GuardCheck{}, record.GuardChecks...)
	for index := range record.GuardChecks {
		record.GuardChecks[index].Categories = append([]string(nil), record.GuardChecks[index].Categories...)
	}
	if record.RequestID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		record.RequestID = hex.EncodeToString(id[:])
	}
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	} else {
		timestamp, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil {
			return fmt.Errorf("invalid access timestamp: %w", err)
		}
		record.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
	}
	<-l.gate
	defer func() { l.gate <- struct{}{} }()
	if l.closed {
		return ErrClosed
	}
	l.queue <- queuedWrite{record: &record}
	return nil
}

// Flush waits for all records queued before this call and syncs the active log.
func (l *Logger) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	barrier := make(chan error, 1)
	select {
	case <-l.gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	if l.closed {
		l.gate <- struct{}{}
		select {
		case <-l.done:
			return l.writerError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case l.queue <- queuedWrite{barrier: barrier}:
		l.gate <- struct{}{}
	case <-ctx.Done():
		l.gate <- struct{}{}
		return ctx.Err()
	}
	select {
	case err := <-barrier:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Logger) Close() error {
	<-l.gate
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.gate <- struct{}{}
	<-l.done
	return l.writerError()
}

func (l *Logger) rememberError(err error) {
	if err == nil {
		return
	}
	l.errMu.Lock()
	defer l.errMu.Unlock()
	// Retain the first failure without an unbounded list on a full or broken disk.
	if l.firstError == nil {
		l.firstError = err
	}
}
func (l *Logger) writerError() error { l.errMu.Lock(); defer l.errMu.Unlock(); return l.firstError }

func (l *Logger) run() {
	defer close(l.done)
	for entry := range l.queue {
		if entry.barrier != nil {
			if l.file != nil {
				l.rememberError(l.file.Sync())
			}
			entry.barrier <- l.writerError()
			continue
		}
		l.rememberError(l.writeJSON(*entry.record))
		l.rememberError(l.writeStatistics(context.Background(), *entry.record))
	}
	if l.file != nil {
		l.rememberError(l.file.Sync())
		l.rememberError(l.file.Close())
		l.file = nil
	}
}

func (l *Logger) open() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	l.file = file
	l.size = info.Size()
	return nil
}

func (l *Logger) writeJSON(record domain.AccessRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode access log: %w", err)
	}
	data = append(data, '\n')
	if l.file == nil {
		if err := l.open(); err != nil {
			return err
		}
	}
	settings := l.settings.Load().(domain.Settings)
	if l.size > 0 && l.size+int64(len(data)) > settings.LogRotationBytes {
		if err := l.rotate(settings.LogGenerations); err != nil {
			return fmt.Errorf("rotate access log: %w", err)
		}
	}
	n, err := l.file.Write(data)
	l.size += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func (l *Logger) rotate(generations int) error {
	if err := l.file.Sync(); err != nil {
		return err
	}
	if err := l.file.Close(); err != nil {
		l.file = nil
		return err
	}
	l.file = nil
	// Compress to a temporary file first; the active source survives failed gzip.
	tmp := l.path + ".rotate.tmp"
	source, err := os.Open(l.path)
	if err != nil {
		return err
	}
	dest, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		source.Close()
		return err
	}
	if err := dest.Chmod(0600); err != nil {
		source.Close()
		dest.Close()
		return err
	}
	gz := gzip.NewWriter(dest)
	_, copyErr := io.Copy(gz, source)
	err = errors.Join(copyErr, gz.Close(), dest.Sync(), dest.Close(), source.Close())
	if err != nil {
		os.Remove(tmp)
		return err
	}
	entries, err := os.ReadDir(filepath.Dir(l.path))
	if err != nil {
		return err
	}
	prefix := filepath.Base(l.path) + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".gz") {
			continue
		}
		generation, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".gz"))
		if parseErr == nil && generation >= generations {
			if err := os.Remove(filepath.Join(filepath.Dir(l.path), name)); err != nil {
				return err
			}
		}
	}
	for generation := generations - 1; generation >= 1; generation-- {
		name := fmt.Sprintf("%s.%d.gz", l.path, generation)
		if err := os.Rename(name, fmt.Sprintf("%s.%d.gz", l.path, generation+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(tmp, l.path+".1.gz"); err != nil {
		return err
	}
	if err := os.Remove(l.path); err != nil {
		return err
	}
	return l.open()
}

func (l *Logger) writeStatistics(ctx context.Context, record domain.AccessRecord) error {
	tags, err := json.Marshal(record.APIKeyTags)
	if err != nil {
		return err
	}
	checks, err := json.Marshal(record.GuardChecks)
	if err != nil {
		return err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO request_stats
  (id,timestamp,source_ip,request_id,api_key_id,api_key_name,api_key_tags,model_id,model_alias,engine_id,engine_name,upstream_model,endpoint,method,status,streaming,duration_ms,ttft_ms,input_tokens,output_tokens,total_tokens,error_code,guard_checks,upstream_ttft_ms)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING`,
		record.RequestID, record.Timestamp, record.SourceIP, record.RequestID, record.APIKeyID, record.APIKeyName, string(tags), record.ModelID, record.ModelAlias, record.EngineID, record.EngineName, record.UpstreamModel, record.Endpoint, record.Method, record.Status, record.Streaming, record.DurationMS, record.TTFTMS, record.InputTokens, record.OutputTokens, record.TotalTokens, record.ErrorCode, string(checks), record.UpstreamTTFTMS)
	if err != nil {
		return fmt.Errorf("insert request statistics: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		return tx.Commit()
	}
	failed := 0
	if record.Status >= 400 || record.ErrorCode != "" {
		failed = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO daily_stats
  (day,model_id,engine_id,api_key_id,model_alias,engine_name,api_key_name,api_key_tags,requests,errors,streaming,duration_ms,input_tokens,output_tokens,total_tokens)
  VALUES (?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)
  ON CONFLICT(day,model_id,engine_id,api_key_id) DO UPDATE SET
  model_alias=excluded.model_alias,engine_name=excluded.engine_name,api_key_name=excluded.api_key_name,api_key_tags=excluded.api_key_tags,
  requests=requests+1,errors=errors+excluded.errors,streaming=streaming+excluded.streaming,duration_ms=duration_ms+excluded.duration_ms,
  input_tokens=input_tokens+excluded.input_tokens,output_tokens=output_tokens+excluded.output_tokens,total_tokens=total_tokens+excluded.total_tokens`,
		record.Timestamp[:10], record.ModelID, record.EngineID, record.APIKeyID, record.ModelAlias, record.EngineName, record.APIKeyName, string(tags), failed, record.Streaming, record.DurationMS, record.InputTokens, record.OutputTokens, record.TotalTokens)
	if err != nil {
		return fmt.Errorf("aggregate request statistics: %w", err)
	}
	return tx.Commit()
}

// Prune removes detailed statistics only; historical daily totals remain intact.
func (l *Logger) Prune(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = l.settings.Load().(domain.Settings).StatisticsRetentionDays
	}
	if err := l.Flush(ctx); err != nil {
		return err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339Nano)
	_, err := l.db.ExecContext(ctx, `DELETE FROM request_stats WHERE timestamp < ?`, cutoff)
	return err
}
