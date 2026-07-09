// Package postgres is the production storage.Store backed by PostgreSQL via
// pgx. The atomic single-use operations (auth-code Consume, refresh-token
// Rotate, device-code SetStatus) are implemented as single SQL statements with
// conditional updates, so their atomicity comes from the row lock the database
// already takes — no advisory locks, no read-modify-write races, correct even
// with many idp replicas sharing one database.
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Store implements storage.Store over a pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to dsn and returns a Store. Callers own Close.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Migrate applies the schema (idempotent).
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func (s *Store) Realms() storage.RealmStore               { return &realmStore{s.pool} }
func (s *Store) Clients() storage.ClientStore             { return &clientStore{s.pool} }
func (s *Store) Users() storage.UserStore                 { return &userStore{s.pool} }
func (s *Store) AuthCodes() storage.AuthCodeStore         { return &authCodeStore{s.pool} }
func (s *Store) RefreshTokens() storage.RefreshTokenStore { return &refreshStore{s.pool} }
func (s *Store) Consents() storage.ConsentStore           { return &consentStore{s.pool} }
func (s *Store) DeviceCodes() storage.DeviceCodeStore     { return &deviceStore{s.pool} }
func (s *Store) Sessions() storage.SessionStore           { return &sessionStore{s.pool} }

// isUniqueViolation reports a Postgres 23505.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return storage.ErrNotFound
	case isUniqueViolation(err):
		return storage.ErrDuplicate
	default:
		return err
	}
}

// ttl helpers convert Go durations (nanoseconds) to/from BIGINT.
func durMillis(d time.Duration) int64  { return int64(d) }
func fromMillis(v int64) time.Duration { return time.Duration(v) }
func nilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
func orZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
