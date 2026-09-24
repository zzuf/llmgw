package database

import (
	"context"
	"errors"
	"strings"
	"time"

	"llmgw/internal/domain"
)

const keyColumns = `id,name,secret_cipher,secret_hash,suffix,enabled,last_used_at,created_at,updated_at,input_safeguard_id,output_safeguard_id,block_controversial`

func scanKey(row scanner) (domain.APIKey, error) {
	var key domain.APIKey
	err := row.Scan(&key.ID, &key.Name, &key.SecretCipher, &key.SecretHash, &key.Suffix, &key.Enabled, &key.LastUsedAt, &key.CreatedAt, &key.UpdatedAt, &key.InputSafeguardID, &key.OutputSafeguardID, &key.BlockControversial)
	key.Masked = "••••" + key.Suffix
	return key, dbError(err)
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+keyColumns+" FROM api_keys ORDER BY name,id")
	if err != nil {
		return nil, err
	}
	keys := []domain.APIKey{}
	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i].Tags, err = stringRows(ctx, s.DB, "SELECT tag FROM api_key_tags WHERE api_key_id=? ORDER BY tag", keys[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func (s *Store) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	key, err := scanKey(s.DB.QueryRowContext(ctx, "SELECT "+keyColumns+" FROM api_keys WHERE id=?", id))
	if err != nil {
		return key, err
	}
	key.Tags, err = stringRows(ctx, s.DB, "SELECT tag FROM api_key_tags WHERE api_key_id=? ORDER BY tag", id)
	return key, err
}

func (s *Store) KeyByHash(ctx context.Context, hash string) (domain.APIKey, error) {
	key, err := scanKey(s.DB.QueryRowContext(ctx, "SELECT "+keyColumns+" FROM api_keys WHERE secret_hash=?", hash))
	if err != nil {
		return key, err
	}
	key.Tags, err = stringRows(ctx, s.DB, "SELECT tag FROM api_key_tags WHERE api_key_id=? ORDER BY tag", key.ID)
	return key, err
}

func (s *Store) SaveAPIKey(ctx context.Context, key *domain.APIKey) error {
	if key == nil || strings.TrimSpace(key.Name) == "" {
		return errors.New("API key name is required")
	}
	if err := ensureID(&key.ID); err != nil {
		return err
	}
	copy := *key
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := scanKey(tx.QueryRowContext(ctx, "SELECT "+keyColumns+" FROM api_keys WHERE id=?", copy.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		copy.CreatedAt = existing.CreatedAt
		copy.LastUsedAt = existing.LastUsedAt
		if copy.SecretCipher == nil {
			copy.SecretCipher = existing.SecretCipher
		}
		if copy.SecretHash == "" {
			copy.SecretHash = existing.SecretHash
		}
		if copy.Suffix == "" {
			copy.Suffix = existing.Suffix
		}
		if copy.Tags == nil {
			copy.Tags, err = stringRows(ctx, tx, "SELECT tag FROM api_key_tags WHERE api_key_id=? ORDER BY tag", copy.ID)
			if err != nil {
				return err
			}
		}
	} else {
		copy.CreatedAt = now()
	}
	if copy.SecretHash == "" || len(copy.SecretCipher) == 0 {
		return errors.New("API key hash and encrypted secret are required")
	}
	copy.UpdatedAt = now()
	tags := make([]string, 0, len(copy.Tags))
	for _, tag := range copy.Tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			tags = append(tags, tag)
		}
	}
	copy.Tags = uniqueStrings(tags)
	_, err = tx.ExecContext(ctx, `INSERT INTO api_keys(`+keyColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,secret_cipher=excluded.secret_cipher,secret_hash=excluded.secret_hash,suffix=excluded.suffix,enabled=excluded.enabled,updated_at=excluded.updated_at,input_safeguard_id=excluded.input_safeguard_id,output_safeguard_id=excluded.output_safeguard_id,block_controversial=excluded.block_controversial`, copy.ID, copy.Name, copy.SecretCipher, copy.SecretHash, copy.Suffix, copy.Enabled, copy.LastUsedAt, copy.CreatedAt, copy.UpdatedAt, copy.InputSafeguardID, copy.OutputSafeguardID, copy.BlockControversial)
	if err != nil {
		return dbError(err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM api_key_tags WHERE api_key_id=?", copy.ID); err != nil {
		return err
	}
	for _, tag := range copy.Tags {
		if _, err := tx.ExecContext(ctx, "INSERT INTO api_key_tags(api_key_id,tag) VALUES(?,?)", copy.ID, tag); err != nil {
			return dbError(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return dbError(err)
	}
	copy.Masked = "••••" + copy.Suffix
	*key = copy
	return nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	return changed(s.DB.ExecContext(ctx, "DELETE FROM api_keys WHERE id=?", id))
}

func (s *Store) TouchAPIKey(ctx context.Context, id string) error {
	return changed(s.DB.ExecContext(ctx, "UPDATE api_keys SET last_used_at=? WHERE id=?", now(), id))
}

const adminColumns = `id,username,password_hash,created_at,updated_at`

func scanAdmin(row scanner) (domain.Admin, error) {
	var a domain.Admin
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.CreatedAt, &a.UpdatedAt)
	return a, dbError(err)
}

func (s *Store) ListAdmins(ctx context.Context) ([]domain.Admin, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+adminColumns+" FROM admins ORDER BY username,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	admins := []domain.Admin{}
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		admins = append(admins, a)
	}
	return admins, rows.Err()
}

func (s *Store) GetAdmin(ctx context.Context, id string) (domain.Admin, error) {
	return scanAdmin(s.DB.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE id=?", id))
}

func (s *Store) AdminByUsername(ctx context.Context, username string) (domain.Admin, error) {
	return scanAdmin(s.DB.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE username=?", username))
}

func (s *Store) CreateAdmin(ctx context.Context, a *domain.Admin, firstOnly bool) error {
	if a == nil || strings.TrimSpace(a.Username) == "" || a.PasswordHash == "" {
		return errors.New("administrator username and password hash are required")
	}
	if err := ensureID(&a.ID); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if firstOnly {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrAlreadySetup
		}
	}
	a.CreatedAt = now()
	a.UpdatedAt = a.CreatedAt
	if _, err := tx.ExecContext(ctx, "INSERT INTO admins("+adminColumns+") VALUES(?,?,?,?,?)", a.ID, a.Username, a.PasswordHash, a.CreatedAt, a.UpdatedAt); err != nil {
		return dbError(err)
	}
	return tx.Commit()
}

func (s *Store) DeleteAdmin(ctx context.Context, id string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT 1 FROM admins WHERE id=?", id).Scan(&exists); err != nil {
		return dbError(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&count); err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastAdmin
	}
	if err := changed(tx.ExecContext(ctx, "DELETE FROM admins WHERE id=?", id)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ChangePassword(ctx context.Context, id, hash string) error {
	if hash == "" {
		return errors.New("password hash is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := changed(tx.ExecContext(ctx, "UPDATE admins SET password_hash=?,updated_at=? WHERE id=?", hash, now(), id)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PutSession(ctx context.Context, session domain.Session) error {
	if session.TokenHash == "" || session.AdminID == "" || session.CSRFToken == "" {
		return errors.New("session token, administrator and CSRF token are required")
	}
	expires, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil {
		return errors.New("invalid session expiration")
	}
	session.ExpiresAt = expires.UTC().Format(time.RFC3339Nano)
	if session.CreatedAt == "" {
		session.CreatedAt = now()
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)`, session.TokenHash, session.AdminID, session.CSRFToken, session.ExpiresAt, session.CreatedAt)
	return dbError(err)
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (domain.Session, error) {
	var session domain.Session
	err := s.DB.QueryRowContext(ctx, "SELECT token_hash,admin_id,csrf_token,expires_at,created_at FROM sessions WHERE token_hash=?", tokenHash).Scan(&session.TokenHash, &session.AdminID, &session.CSRFToken, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return session, dbError(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		_, _ = s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", tokenHash)
		return domain.Session{}, ErrNotFound
	}
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", tokenHash)
	return err
}
