package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"llmgw/internal/domain"
)

const engineColumns = `id,name,base_url,type,detected_type,auth_type,secret_cipher,enabled,status,last_check,last_success,last_error,latency_ms,created_at,updated_at`

func scanEngine(row scanner) (domain.Engine, error) {
	var e domain.Engine
	err := row.Scan(&e.ID, &e.Name, &e.BaseURL, &e.Type, &e.DetectedType, &e.AuthType, &e.SecretCipher, &e.Enabled, &e.Status, &e.LastCheck, &e.LastSuccess, &e.LastError, &e.LatencyMS, &e.CreatedAt, &e.UpdatedAt)
	e.HasSecret = len(e.SecretCipher) > 0
	return e, dbError(err)
}

func (s *Store) ListEngines(ctx context.Context) ([]domain.Engine, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+engineColumns+" FROM engines ORDER BY name,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	engines := []domain.Engine{}
	for rows.Next() {
		e, err := scanEngine(rows)
		if err != nil {
			return nil, err
		}
		engines = append(engines, e)
	}
	return engines, rows.Err()
}

func (s *Store) GetEngine(ctx context.Context, id string) (domain.Engine, error) {
	return scanEngine(s.DB.QueryRowContext(ctx, "SELECT "+engineColumns+" FROM engines WHERE id=?", id))
}

func (s *Store) SaveEngine(ctx context.Context, e *domain.Engine) error {
	if e == nil || strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.BaseURL) == "" {
		return errors.New("engine name and base URL are required")
	}
	if err := ensureID(&e.ID); err != nil {
		return err
	}
	if e.Type == "" {
		e.Type = "auto"
	}
	if e.AuthType == "" {
		e.AuthType = "none"
	}
	if e.Status == "" {
		e.Status = "Unknown"
	}
	stamp := now()
	if e.CreatedAt == "" {
		e.CreatedAt = stamp
	}
	e.UpdatedAt = stamp
	_, err := s.DB.ExecContext(ctx, `INSERT INTO engines(`+engineColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,base_url=excluded.base_url,type=excluded.type,detected_type=excluded.detected_type,auth_type=excluded.auth_type,secret_cipher=excluded.secret_cipher,enabled=excluded.enabled,status=excluded.status,last_check=excluded.last_check,last_success=excluded.last_success,last_error=excluded.last_error,latency_ms=excluded.latency_ms,updated_at=excluded.updated_at`, e.ID, e.Name, e.BaseURL, e.Type, e.DetectedType, e.AuthType, e.SecretCipher, e.Enabled, e.Status, e.LastCheck, e.LastSuccess, e.LastError, e.LatencyMS, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return dbError(err)
	}
	stored, err := s.GetEngine(ctx, e.ID)
	if err == nil {
		*e = stored
	}
	return err
}

func (s *Store) DeleteEngine(ctx context.Context, id string) error {
	return changed(s.DB.ExecContext(ctx, "DELETE FROM engines WHERE id=?", id))
}

func (s *Store) UpdateHealth(ctx context.Context, id, status, lastError string, latencyMS float64, detectedType string) error {
	stamp := now()
	return changed(s.DB.ExecContext(ctx, `UPDATE engines SET status=?,last_check=?,last_success=CASE WHEN ? THEN ? ELSE last_success END,last_error=?,latency_ms=?,detected_type=CASE WHEN ?='' THEN detected_type ELSE ? END WHERE id=?`, status, stamp, strings.EqualFold(status, "online"), stamp, lastError, latencyMS, detectedType, detectedType, id))
}

// SyncModels is called only after successful discovery. Missing IDs remain in the
// catalog, so a later reappearance restores availability without changing policy.
func (s *Store) SyncModels(ctx context.Context, engineID string, models []domain.UpstreamModel) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT 1 FROM engines WHERE id=?", engineID).Scan(&exists); err != nil {
		return dbError(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE upstream_models SET available=0 WHERE engine_id=?", engineID); err != nil {
		return err
	}
	stamp := now()
	for _, m := range models {
		if strings.TrimSpace(m.UpstreamID) == "" {
			return errors.New("upstream model ID is required")
		}
		if m.Capabilities == nil {
			m.Capabilities = map[string]bool{}
		}
		caps, err := json.Marshal(m.Capabilities)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO upstream_models(engine_id,upstream_id,display_name,available,capabilities,last_seen) VALUES(?,?,?,1,?,?) ON CONFLICT(engine_id,upstream_id) DO UPDATE SET display_name=excluded.display_name,available=1,capabilities=excluded.capabilities,last_seen=excluded.last_seen`, engineID, m.UpstreamID, m.DisplayName, string(caps), stamp); err != nil {
			return dbError(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE models SET available=COALESCE((SELECT available FROM upstream_models WHERE engine_id=models.engine_id AND upstream_id=models.upstream_model_id),0) WHERE engine_id=?`, engineID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListUpstreamModels(ctx context.Context) ([]domain.UpstreamModel, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT u.engine_id,u.upstream_id,u.display_name,u.available,u.capabilities,u.last_seen,EXISTS(SELECT 1 FROM models m WHERE m.engine_id=u.engine_id AND m.upstream_model_id=u.upstream_id) FROM upstream_models u ORDER BY u.engine_id,u.upstream_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	models := []domain.UpstreamModel{}
	for rows.Next() {
		var m domain.UpstreamModel
		var caps string
		if err := rows.Scan(&m.EngineID, &m.UpstreamID, &m.DisplayName, &m.Available, &caps, &m.LastSeen, &m.Registered); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(caps), &m.Capabilities); err != nil {
			return nil, err
		}
		if m.Capabilities == nil {
			m.Capabilities = map[string]bool{}
		}
		models = append(models, m)
	}
	return models, rows.Err()
}

func upstreamModel(ctx context.Context, tx *sql.Tx, engineID, upstreamID string) (domain.UpstreamModel, error) {
	var m domain.UpstreamModel
	var caps string
	err := tx.QueryRowContext(ctx, `SELECT engine_id,upstream_id,display_name,available,capabilities,last_seen FROM upstream_models WHERE engine_id=? AND upstream_id=?`, engineID, upstreamID).Scan(&m.EngineID, &m.UpstreamID, &m.DisplayName, &m.Available, &caps, &m.LastSeen)
	if err != nil {
		return m, dbError(err)
	}
	err = json.Unmarshal([]byte(caps), &m.Capabilities)
	if m.Capabilities == nil {
		m.Capabilities = map[string]bool{}
	}
	return m, err
}
