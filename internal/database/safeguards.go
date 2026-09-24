package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"llmgw/internal/domain"
)

const safeguardColumns = `g.id,g.name,g.engine_id,g.upstream_model_id,g.adapter,g.enabled,u.available,g.last_check,g.last_error,g.created_at,g.updated_at`
const safeguardJoin = ` FROM safeguards g JOIN upstream_models u ON u.engine_id=g.engine_id AND u.upstream_id=g.upstream_model_id`

func scanSafeguard(row scanner) (domain.Safeguard, error) {
	var g domain.Safeguard
	err := row.Scan(&g.ID, &g.Name, &g.EngineID, &g.UpstreamModelID, &g.Adapter, &g.Enabled, &g.Available, &g.LastCheck, &g.LastError, &g.CreatedAt, &g.UpdatedAt)
	return g, dbError(err)
}

func (s *Store) ListSafeguards(ctx context.Context) ([]domain.Safeguard, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+safeguardColumns+safeguardJoin+" ORDER BY g.name,g.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Safeguard{}
	for rows.Next() {
		g, err := scanSafeguard(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

func (s *Store) GetSafeguard(ctx context.Context, id string) (domain.Safeguard, error) {
	return scanSafeguard(s.DB.QueryRowContext(ctx, "SELECT "+safeguardColumns+safeguardJoin+" WHERE g.id=?", id))
}

func (s *Store) SaveSafeguard(ctx context.Context, g *domain.Safeguard) error {
	if g == nil || strings.TrimSpace(g.Name) == "" {
		return errors.New("safeguard name is required")
	}
	if g.Adapter != "qwen3guard_gen" {
		return errors.New("unsupported safeguard adapter")
	}
	if strings.TrimSpace(g.EngineID) == "" || strings.TrimSpace(g.UpstreamModelID) == "" {
		return errors.New("safeguard engine and upstream model are required")
	}
	copy := *g
	copy.Name = strings.TrimSpace(copy.Name)
	if err := ensureID(&copy.ID); err != nil {
		return err
	}
	stamp := now()
	// Health-check metadata is solely updated by UpdateSafeguardCheck. In particular,
	// an ordinary edit cannot overwrite a concurrently completed connection check.
	_, err := s.DB.ExecContext(ctx, `INSERT INTO safeguards(id,name,engine_id,upstream_model_id,adapter,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,engine_id=excluded.engine_id,upstream_model_id=excluded.upstream_model_id,adapter=excluded.adapter,enabled=excluded.enabled,updated_at=excluded.updated_at`, copy.ID, copy.Name, copy.EngineID, copy.UpstreamModelID, copy.Adapter, copy.Enabled, stamp, stamp)
	if err != nil {
		return dbError(err)
	}
	stored, err := s.GetSafeguard(ctx, copy.ID)
	if err == nil {
		*g = stored
	}
	return err
}

func (s *Store) DeleteSafeguard(ctx context.Context, id string) error {
	return changed(s.DB.ExecContext(ctx, "DELETE FROM safeguards WHERE id=?", id))
}

func (s *Store) UpdateSafeguardCheck(ctx context.Context, id, lastCheck, lastError string) error {
	return changed(s.DB.ExecContext(ctx, "UPDATE safeguards SET last_check=?,last_error=? WHERE id=?", lastCheck, lastError, id))
}

// LoadSafeguards captures all policies, availability and engine credentials in a
// single short transaction. It never holds a database connection during inference.
func (s *Store) LoadSafeguards(ctx context.Context, ids []string) (map[string]domain.SafeguardBinding, error) {
	result := make(map[string]domain.SafeguardBinding, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, ok := result[id]; ok {
			continue
		}
		g, err := scanSafeguard(tx.QueryRowContext(ctx, "SELECT "+safeguardColumns+safeguardJoin+" WHERE g.id=?", id))
		if err != nil {
			return nil, err
		}
		e, err := scanEngine(tx.QueryRowContext(ctx, "SELECT "+engineColumns+" FROM engines WHERE id=?", g.EngineID))
		if err != nil {
			return nil, err
		}
		result[id] = domain.SafeguardBinding{Safeguard: g, Engine: e}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
