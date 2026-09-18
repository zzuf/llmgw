package logging

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"llmgw/internal/domain"
)

// Dashboard returns configuration counts and today's UTC usage, including
// started streams whose final result was an error after an HTTP 200 response.
func Dashboard(ctx context.Context, db *sql.DB) (map[string]any, error) {
	var engines, online, offline, degraded, published, unavailable, keys, requests, failures, streaming, input, output, total int64
	var duration float64
	err := db.QueryRowContext(ctx, `SELECT
  (SELECT COUNT(*) FROM engines),
  (SELECT COUNT(*) FROM engines WHERE lower(status)='online'),
  (SELECT COUNT(*) FROM engines WHERE lower(status)='offline'),
  (SELECT COUNT(*) FROM engines WHERE lower(status)='degraded'),
  (SELECT COUNT(*) FROM models WHERE published=1),
  (SELECT COUNT(*) FROM models WHERE available=0),
  (SELECT COUNT(*) FROM api_keys),
  COALESCE(SUM(requests),0),COALESCE(SUM(errors),0),COALESCE(SUM(streaming),0),
  COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(total_tokens),0),COALESCE(SUM(duration_ms),0)
  FROM daily_stats WHERE day=?`, time.Now().UTC().Format("2006-01-02")).Scan(&engines, &online, &offline, &degraded, &published, &unavailable, &keys, &requests, &failures, &streaming, &input, &output, &total, &duration)
	if err != nil {
		return nil, err
	}
	rate, average := rates(requests, failures, duration)
	return map[string]any{"engines": engines, "online": online, "offline": offline, "degraded": degraded, "published_models": published, "unavailable_models": unavailable, "api_keys": keys, "today_requests": requests, "input_tokens": input, "output_tokens": output, "total_tokens": total, "error_rate": rate, "average_response_ms": average, "streaming_requests": streaming}, nil
}

func rates(requests, failures int64, duration float64) (float64, float64) {
	if requests == 0 {
		return 0, 0
	}
	return float64(failures) / float64(requests), duration / float64(requests)
}

// Statistics reads daily aggregates so deleting configuration and pruning
// detailed requests cannot remove historical usage. Error rates are fractions.
func Statistics(ctx context.Context, db *sql.DB, group string, days int) ([]map[string]any, error) {
	if group == "" {
		group = "day"
	}
	if days <= 0 {
		days = 30
	}
	if days > 36500 {
		days = 36500
	}
	var keyColumn, nameColumn string
	switch group {
	case "model":
		keyColumn = "model_id"
		nameColumn = "model_alias"
	case "engine":
		keyColumn = "engine_id"
		nameColumn = "engine_name"
	case "api_key":
		keyColumn = "api_key_id"
		nameColumn = "api_key_name"
	case "day":
		keyColumn = "day"
		nameColumn = "day"
	default:
		return nil, fmt.Errorf("unknown statistics group %q", group)
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, 1-days).Format("2006-01-02")
	// SQLite ties bare snapshot columns to the row providing the single MAX(day),
	// so renamed/deleted objects use their most recent available snapshot.
	query := `SELECT ` + keyColumn + `,` + nameColumn + `,api_key_tags,MAX(day),SUM(requests),SUM(errors),SUM(streaming),SUM(duration_ms),SUM(input_tokens),SUM(output_tokens),SUM(total_tokens) FROM daily_stats WHERE day>=? AND day<=? GROUP BY ` + keyColumn + ` ORDER BY SUM(requests) DESC,` + keyColumn
	if group == "day" {
		query = `SELECT day,day,api_key_tags,MAX(day),SUM(requests),SUM(errors),SUM(streaming),SUM(duration_ms),SUM(input_tokens),SUM(output_tokens),SUM(total_tokens) FROM daily_stats WHERE day>=? AND day<=? GROUP BY day ORDER BY day DESC`
	}
	rows, err := db.QueryContext(ctx, query, start, now.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var key, name, tags, lastDay string
		var requests, failures, streaming, input, output, total int64
		var duration float64
		if err := rows.Scan(&key, &name, &tags, &lastDay, &requests, &failures, &streaming, &duration, &input, &output, &total); err != nil {
			return nil, err
		}
		rate, average := rates(requests, failures, duration)
		row := map[string]any{"group": group, "key": key, "name": name, "requests": requests, "errors": failures, "streaming_requests": streaming, "duration_ms": duration, "input_tokens": input, "output_tokens": output, "total_tokens": total, "error_rate": rate, "average_response_ms": average, "last_day": lastDay, keyColumn: key, nameColumn: name}
		if group == "api_key" {
			var decoded []string
			if err := json.Unmarshal([]byte(tags), &decoded); err != nil {
				return nil, fmt.Errorf("decode historical API key tags: %w", err)
			}
			if decoded == nil {
				decoded = []string{}
			}
			row["api_key_tags"] = decoded
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func pagination(page, pageSize int) (int, int64) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if int64(page-1) > math.MaxInt64/int64(pageSize) {
		return pageSize, math.MaxInt64
	}
	return pageSize, int64(page-1) * int64(pageSize)
}

func literalLike(value string) string {
	escape := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)
	return "%" + escape.Replace(value) + "%"
}

// Search terms support field:value prefixes and ordinary literal text. Column
// names come only from these internal allowlists; all user values are bound.
func searchWhere(filter string, fields map[string][]string, all []string) (string, []any) {
	if strings.TrimSpace(filter) == "" {
		return "", nil
	}
	terms := strings.Fields(filter)
	clauses := []string{}
	args := []any{}
	for _, term := range terms {
		columns := all
		value := term
		if prefix, remainder, ok := strings.Cut(term, ":"); ok {
			if selected, exists := fields[strings.ToLower(prefix)]; exists {
				columns = selected
				value = remainder
			}
		}
		if value == "" {
			continue
		}
		alternatives := make([]string, 0, len(columns))
		for _, column := range columns {
			alternatives = append(alternatives, "CAST("+column+" AS TEXT) LIKE ? ESCAPE '\\'")
			args = append(args, literalLike(value))
		}
		clauses = append(clauses, "("+strings.Join(alternatives, " OR ")+")")
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

var accessFields = map[string][]string{
	"model": {"model_id", "model_alias", "upstream_model"}, "engine": {"engine_id", "engine_name"}, "key": {"api_key_id", "api_key_name", "api_key_tags"}, "source": {"source_ip"}, "endpoint": {"endpoint"}, "status": {"status"}, "request": {"request_id"}, "error": {"error_code"},
}
var accessSearch = []string{"request_id", "source_ip", "api_key_id", "api_key_name", "api_key_tags", "model_id", "model_alias", "engine_id", "engine_name", "upstream_model", "endpoint", "method", "status", "error_code"}

// AccessLogs returns prompt-free detail rows with a stable timestamp/id order.
func AccessLogs(ctx context.Context, db *sql.DB, filter string, page, pageSize int) ([]domain.AccessRecord, int, error) {
	where, args := searchWhere(filter, accessFields, accessSearch)
	limit, offset := pagination(page, pageSize)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_stats`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT timestamp,source_ip,request_id,api_key_id,api_key_name,api_key_tags,model_id,model_alias,engine_id,engine_name,upstream_model,endpoint,method,status,streaming,duration_ms,ttft_ms,input_tokens,output_tokens,total_tokens,error_code FROM request_stats`+where+` ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []domain.AccessRecord{}
	for rows.Next() {
		var record domain.AccessRecord
		var tags string
		if err := rows.Scan(&record.Timestamp, &record.SourceIP, &record.RequestID, &record.APIKeyID, &record.APIKeyName, &tags, &record.ModelID, &record.ModelAlias, &record.EngineID, &record.EngineName, &record.UpstreamModel, &record.Endpoint, &record.Method, &record.Status, &record.Streaming, &record.DurationMS, &record.TTFTMS, &record.InputTokens, &record.OutputTokens, &record.TotalTokens, &record.ErrorCode); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal([]byte(tags), &record.APIKeyTags); err != nil {
			return nil, 0, fmt.Errorf("decode request API key tags: %w", err)
		}
		if record.APIKeyTags == nil {
			record.APIKeyTags = []string{}
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return result, total, nil
}

var auditFields = map[string][]string{"actor": {"actor_id", "actor_name"}, "source": {"source_ip"}, "action": {"action"}, "target": {"target"}, "result": {"result"}}
var auditSearch = []string{"actor_id", "actor_name", "source_ip", "action", "target", "result", "detail"}

func AuditLogs(ctx context.Context, db *sql.DB, filter string, page, pageSize int) ([]domain.Audit, int, error) {
	where, args := searchWhere(filter, auditFields, auditSearch)
	limit, offset := pagination(page, pageSize)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,timestamp,actor_id,actor_name,source_ip,action,target,result,detail FROM audit_logs`+where+` ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []domain.Audit{}
	for rows.Next() {
		var audit domain.Audit
		if err := rows.Scan(&audit.ID, &audit.Timestamp, &audit.ActorID, &audit.ActorName, &audit.SourceIP, &audit.Action, &audit.Target, &audit.Result, &audit.Detail); err != nil {
			return nil, 0, err
		}
		result = append(result, audit)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return result, total, nil
}
