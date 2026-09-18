package database

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"llmgw/internal/domain"
)

const modelColumns = `id,alias,engine_id,upstream_model_id,display_name,published,available,created_at,updated_at`

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func scanModel(row scanner) (domain.Model, error) {
	var m domain.Model
	err := row.Scan(&m.ID, &m.Alias, &m.EngineID, &m.UpstreamModelID, &m.DisplayName, &m.Published, &m.Available, &m.CreatedAt, &m.UpdatedAt)
	return m, dbError(err)
}

func modelChildren(ctx context.Context, q queryer, m *domain.Model) error {
	var err error
	m.AllowedIPs, err = stringRows(ctx, q, "SELECT cidr FROM model_allowed_ips WHERE model_id=? ORDER BY cidr", m.ID)
	if err != nil {
		return err
	}
	m.AllowedAPIKeys, err = stringRows(ctx, q, "SELECT api_key_id FROM model_allowed_api_keys WHERE model_id=? ORDER BY api_key_id", m.ID)
	if err != nil {
		return err
	}
	rows, err := q.QueryContext(ctx, "SELECT capability,enabled FROM model_capabilities WHERE model_id=? ORDER BY capability", m.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	m.Capabilities = map[string]bool{}
	for rows.Next() {
		var name string
		var enabled bool
		if err := rows.Scan(&name, &enabled); err != nil {
			return err
		}
		m.Capabilities[name] = enabled
	}
	return rows.Err()
}

func stringRows(ctx context.Context, q queryer, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Store) ListModels(ctx context.Context) ([]domain.Model, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT "+modelColumns+" FROM models ORDER BY alias,id")
	if err != nil {
		return nil, err
	}
	models := []domain.Model{}
	for rows.Next() {
		m, err := scanModel(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		models = append(models, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range models {
		if err := modelChildren(ctx, tx, &models[i]); err != nil {
			return nil, err
		}
	}
	return models, tx.Commit()
}

func (s *Store) GetModel(ctx context.Context, id string) (domain.Model, error) {
	return s.readModel(ctx, "SELECT "+modelColumns+" FROM models WHERE id=?", id)
}

func (s *Store) ModelByAlias(ctx context.Context, alias string) (domain.Model, error) {
	return s.readModel(ctx, "SELECT "+modelColumns+" FROM models WHERE alias=?", alias)
}

func (s *Store) readModel(ctx context.Context, query, value string) (domain.Model, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return domain.Model{}, err
	}
	defer tx.Rollback()
	m, err := scanModel(tx.QueryRowContext(ctx, query, value))
	if err != nil {
		return m, err
	}
	if err := modelChildren(ctx, tx, &m); err != nil {
		return m, err
	}
	return m, tx.Commit()
}

func normalizeIPs(ips []string) ([]string, error) {
	result := []string{}
	for _, value := range ips {
		value = strings.TrimSpace(value)
		var prefix netip.Prefix
		if strings.Contains(value, "/") {
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid IP or CIDR %q", value)
			}
			prefix = p
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return nil, fmt.Errorf("invalid mapped IPv4 prefix %q", value)
				}
				prefix = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("invalid IP or CIDR %q", value)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		result = append(result, prefix.Masked().String())
	}
	return uniqueStrings(result), nil
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

// SaveModel atomically stores policy and effective capabilities. Nil collections
// preserve existing policy on update. At creation, nil IPs mean loopback defaults,
// nil capabilities inherit discovery metadata, and explicit empty lists stay empty.
func (s *Store) SaveModel(ctx context.Context, m *domain.Model) error {
	if m == nil || !aliasPattern.MatchString(m.Alias) {
		return errors.New("invalid alias: use 1–128 letters, digits, dots, colons, slashes, underscores or hyphens, starting with a letter or digit")
	}
	if err := ensureID(&m.ID); err != nil {
		return err
	}
	copy := *m
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := scanModel(tx.QueryRowContext(ctx, "SELECT "+modelColumns+" FROM models WHERE id=?", copy.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	create := errors.Is(err, ErrNotFound)
	if !create {
		if err := modelChildren(ctx, tx, &existing); err != nil {
			return err
		}
		copy.CreatedAt = existing.CreatedAt
		if copy.AllowedIPs == nil {
			copy.AllowedIPs = existing.AllowedIPs
		}
		if copy.AllowedAPIKeys == nil {
			copy.AllowedAPIKeys = existing.AllowedAPIKeys
		}
		if copy.Capabilities == nil {
			copy.Capabilities = existing.Capabilities
		}
	}
	upstream, err := upstreamModel(ctx, tx, copy.EngineID, copy.UpstreamModelID)
	if err != nil {
		return fmt.Errorf("upstream model: %w", err)
	}
	if create {
		copy.CreatedAt = now()
		if copy.AllowedIPs == nil {
			copy.AllowedIPs = []string{"127.0.0.1/32", "::1/128"}
		}
		if copy.Capabilities == nil {
			copy.Capabilities = upstream.Capabilities
		}
	}
	copy.UpdatedAt = now()
	copy.Available = upstream.Available
	if copy.DisplayName == "" {
		copy.DisplayName = upstream.DisplayName
	}
	copy.AllowedIPs, err = normalizeIPs(copy.AllowedIPs)
	if err != nil {
		return err
	}
	copy.AllowedAPIKeys = uniqueStrings(copy.AllowedAPIKeys)
	_, err = tx.ExecContext(ctx, `INSERT INTO models(`+modelColumns+`) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET alias=excluded.alias,engine_id=excluded.engine_id,upstream_model_id=excluded.upstream_model_id,display_name=excluded.display_name,published=excluded.published,available=excluded.available,updated_at=excluded.updated_at`, copy.ID, copy.Alias, copy.EngineID, copy.UpstreamModelID, copy.DisplayName, copy.Published, copy.Available, copy.CreatedAt, copy.UpdatedAt)
	if err != nil {
		return dbError(err)
	}
	for _, table := range []string{"model_allowed_ips", "model_allowed_api_keys", "model_capabilities"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE model_id=?", copy.ID); err != nil {
			return err
		}
	}
	for _, cidr := range copy.AllowedIPs {
		if _, err := tx.ExecContext(ctx, "INSERT INTO model_allowed_ips(model_id,cidr) VALUES(?,?)", copy.ID, cidr); err != nil {
			return dbError(err)
		}
	}
	for _, keyID := range copy.AllowedAPIKeys {
		if _, err := tx.ExecContext(ctx, "INSERT INTO model_allowed_api_keys(model_id,api_key_id) VALUES(?,?)", copy.ID, keyID); err != nil {
			return dbError(err)
		}
	}
	for capability, enabled := range copy.Capabilities {
		if strings.TrimSpace(capability) == "" {
			return errors.New("capability names must not be empty")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO model_capabilities(model_id,capability,enabled) VALUES(?,?,?)", copy.ID, capability, enabled); err != nil {
			return dbError(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return dbError(err)
	}
	*m = copy
	return nil
}

func (s *Store) DeleteModel(ctx context.Context, id string) error {
	return changed(s.DB.ExecContext(ctx, "DELETE FROM models WHERE id=?", id))
}
