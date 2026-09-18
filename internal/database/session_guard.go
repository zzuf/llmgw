package database

import (
	"context"
	"llmgw/internal/domain"
)

// PutSessionForAdmin rejects a successful password check that became stale while
// Argon2 was running. The predicate and insertion are one atomic SQL statement.
func (s *Store) PutSessionForAdmin(ctx context.Context, session domain.Session, expectedHash string) error {
	result, e := s.DB.ExecContext(ctx, `INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,created_at)
 SELECT ?,id,?,?,? FROM admins WHERE id=? AND password_hash=?`, session.TokenHash, session.CSRFToken, session.ExpiresAt, session.CreatedAt, session.AdminID, expectedHash)
	if e != nil {
		return dbError(e)
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
