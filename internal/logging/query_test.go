package logging

import (
	"context"
	"testing"
	"time"

	"llmgw/internal/domain"
)

func TestDashboardCountsStreamingFailuresAndEmptyDatabase(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	ctx := context.Background()
	empty, err := Dashboard(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if empty["today_requests"] != int64(0) || empty["error_rate"] != float64(0) {
		t.Fatalf("bad empty summary: %#v", empty)
	}
	for _, status := range []string{"Online", "Offline", "Degraded"} {
		_, err := db.Exec(`INSERT INTO engines(id,name,base_url,status,created_at,updated_at) VALUES(?,?,?,?,'','')`, status, status, "http://localhost", status)
		if err != nil {
			t.Fatal(err)
		}
	}
	a := sampleRecord("a")
	a.ErrorCode = "stream_interrupted" // HTTP 200 may already have been sent.
	b := sampleRecord("b")
	b.Streaming = false
	b.DurationMS = 300
	for _, r := range []domain.AccessRecord{a, b} {
		if err := logger.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := Dashboard(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int64{"engines": 3, "online": 1, "offline": 1, "degraded": 1, "today_requests": 2, "input_tokens": 14, "output_tokens": 22, "total_tokens": 36, "streaming_requests": 1} {
		if got[key] != want {
			t.Errorf("%s got %v want %d", key, got[key], want)
		}
	}
	if got["error_rate"] != float64(0.5) || got["average_response_ms"] != float64(200) {
		t.Errorf("wrong rates: %#v", got)
	}
}

func TestStatisticsUsesRetainedDailyHistoryAndRejectsInvalidGrouping(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	ctx := context.Background()
	a := sampleRecord("old")
	a.Timestamp = time.Now().UTC().AddDate(0, 0, -100).Format(time.RFC3339Nano)
	b := sampleRecord("recent")
	b.APIKeyID = ""
	b.APIKeyName = ""
	b.APIKeyTags = nil
	for _, r := range []domain.AccessRecord{a, b} {
		if err := logger.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Prune(ctx, 90); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"model", "engine", "api_key", "day"} {
		rows, err := Statistics(ctx, db, group, 180)
		if err != nil {
			t.Fatal(err)
		}
		var requests int64
		for _, row := range rows {
			requests += row["requests"].(int64)
		}
		if requests != 2 {
			t.Errorf("%s lost history: %v", group, rows)
		}
	}
	rows, err := Statistics(ctx, db, "model", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["requests"] != int64(1) {
		t.Fatalf("date range ignored: %#v", rows)
	}
	if _, err := Statistics(ctx, db, "day; DROP TABLE daily_stats", 30); err == nil {
		t.Fatal("invalid SQL grouping accepted")
	}
}

func TestAccessAndAuditQueriesFilterPaginateAndExcludePrompts(t *testing.T) {
	logger, db, _ := newTestLogger(t, domain.DefaultSettings())
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		r := sampleRecord(id)
		if id == "c" {
			r.Status = 503
			r.ModelAlias = "other"
		}
		if err := logger.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, total, err := AccessLogs(ctx, db, "model:public status:200", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 1 || rows[0].Prompt != nil || len(rows[0].APIKeyTags) != 1 {
		t.Fatalf("bad filtered access logs %d %#v", total, rows)
	}
	_, total, err = AccessLogs(ctx, db, "' OR 1=1 --", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("filter interpreted as SQL: %d", total)
	}
	_, total, err = AccessLogs(ctx, db, "%", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("wildcard not literal: %d", total)
	}
	_, err = db.Exec(`INSERT INTO audit_logs(id,timestamp,actor_id,actor_name,source_ip,action,target,result,detail) VALUES ('audit','2026-01-01T00:00:00Z','admin','Alice','127.0.0.1','engine.create','engine1','success','safe detail')`)
	if err != nil {
		t.Fatal(err)
	}
	audits, total, err := AuditLogs(ctx, db, "Alice", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(audits) != 1 || audits[0].Action != "engine.create" {
		t.Fatalf("bad audit query %d %#v", total, audits)
	}
}
