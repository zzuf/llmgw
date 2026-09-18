package database

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"

	"llmgw/internal/domain"
)

func settingsValues(settings domain.Settings) (map[string]json.RawMessage, error) {
	contents, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	err = json.Unmarshal(contents, &values)
	return values, err
}

func (s *Store) initializeSettings(ctx context.Context) error {
	values, err := settingsValues(domain.DefaultSettings())
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", key, string(value)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Settings(ctx context.Context) (domain.Settings, error) {
	settings := domain.DefaultSettings()
	rows, err := s.DB.QueryContext(ctx, "SELECT key,value FROM settings")
	if err != nil {
		return settings, err
	}
	defer rows.Close()
	values := map[string]json.RawMessage{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return settings, err
		}
		values[key] = json.RawMessage(value)
	}
	if err := rows.Err(); err != nil {
		return settings, err
	}
	contents, err := json.Marshal(values)
	if err != nil {
		return settings, err
	}
	err = json.Unmarshal(contents, &settings)
	return settings, err
}

func (s *Store) SaveSettings(ctx context.Context, settings domain.Settings) error {
	_, port, err := net.SplitHostPort(settings.ListenAddress)
	if err != nil {
		return errors.New("listen address must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return errors.New("listen port must be between 0 and 65535")
	}
	if settings.HealthIntervalSeconds <= 0 || settings.RequestTimeoutSeconds <= 0 || settings.LogRotationBytes <= 0 || settings.LogGenerations <= 0 || settings.StatisticsRetentionDays <= 0 || settings.BackupRetentionDays <= 0 {
		return errors.New("intervals, timeouts, sizes and retention values must be positive")
	}
	values, err := settingsValues(settings)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, string(value)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddAudit(ctx context.Context, event domain.Audit) error {
	if err := ensureID(&event.ID); err != nil {
		return err
	}
	if event.Timestamp == "" {
		event.Timestamp = now()
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_logs(id,timestamp,actor_id,actor_name,source_ip,action,target,result,detail) VALUES(?,?,?,?,?,?,?,?,?)`, event.ID, event.Timestamp, event.ActorID, event.ActorName, event.SourceIP, event.Action, event.Target, event.Result, event.Detail)
	return dbError(err)
}
