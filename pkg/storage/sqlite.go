package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStorage implements Storage using an embedded SQLite database.
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage initializes a SQLite-backed Storage instance.
// It configures WAL mode and creates required tables if they don't already exist.
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	// Enable WAL mode and set busy timeout for high concurrency
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed opening sqlite database: %w", err)
	}

	// Bounded connection pool for SQLite
	db.SetMaxOpenConns(1) // SQLite works best with serialized writes or WAL mode
	db.SetMaxIdleConns(1)

	s := &SQLiteStorage{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed initializing sqlite schema: %w", err)
	}

	return s, nil
}

func (s *SQLiteStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS certificates (
		serial TEXT PRIMARY KEY,
		subject TEXT NOT NULL,
		issuer TEXT NOT NULL,
		not_before DATETIME NOT NULL,
		not_after DATETIME NOT NULL,
		raw_der BLOB NOT NULL,
		pem BLOB NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS revocations (
		serial TEXT PRIMARY KEY,
		revoked_at DATETIME NOT NULL,
		reason INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS serials (
		serial TEXT PRIMARY KEY,
		issued_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_cert_revoked ON certificates(revoked);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveCertificate persists a new certificate record.
func (s *SQLiteStorage) SaveCertificate(ctx context.Context, cert *CertificateRecord) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate record", ErrInvalidInput)
	}
	serial := NormalizeSerial(cert.Serial)
	if serial == "" {
		return fmt.Errorf("%w: empty serial number", ErrInvalidInput)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check for duplicates
	var exists int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE serial = ?", serial).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return fmt.Errorf("%w: certificate with serial %s", ErrAlreadyExists, serial)
	}

	revokedInt := 0
	if cert.Revoked {
		revokedInt = 1
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO certificates (serial, subject, issuer, not_before, not_after, raw_der, pem, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, serial, cert.Subject, cert.Issuer, cert.NotBefore.UTC(), cert.NotAfter.UTC(), cert.RawDER, cert.PEM, revokedInt)
	if err != nil {
		return err
	}

	// Also ensure serial is recorded in serials table
	_, _ = tx.ExecContext(ctx, "INSERT OR IGNORE INTO serials (serial, issued_at) VALUES (?, ?)", serial, time.Now().UTC())

	return tx.Commit()
}

// GetCertificate fetches a certificate record by its serial number.
func (s *SQLiteStorage) GetCertificate(ctx context.Context, serial string) (*CertificateRecord, error) {
	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return nil, fmt.Errorf("%w: empty serial number", ErrInvalidInput)
	}

	var rec CertificateRecord
	var revokedInt int
	var notBefore, notAfter time.Time

	row := s.db.QueryRowContext(ctx, `
		SELECT serial, subject, issuer, not_before, not_after, raw_der, pem, revoked
		FROM certificates
		WHERE serial = ?
	`, normSerial)

	err := row.Scan(&rec.Serial, &rec.Subject, &rec.Issuer, &notBefore, &notAfter, &rec.RawDER, &rec.PEM, &revokedInt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: certificate %s", ErrNotFound, normSerial)
	}
	if err != nil {
		return nil, err
	}

	rec.NotBefore = notBefore.UTC()
	rec.NotAfter = notAfter.UTC()
	rec.Revoked = (revokedInt == 1)

	return &rec, nil
}

// RevokeCertificate marks a certificate as revoked and records the revocation reason.
func (s *SQLiteStorage) RevokeCertificate(ctx context.Context, serial string, reason int, revokedAt time.Time) error {
	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return fmt.Errorf("%w: empty serial number", ErrInvalidInput)
	}

	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check certificate exists
	var revokedInt int
	err = tx.QueryRowContext(ctx, "SELECT revoked FROM certificates WHERE serial = ?", normSerial).Scan(&revokedInt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: cannot revoke non-existent certificate %s", ErrNotFound, normSerial)
	}
	if err != nil {
		return err
	}

	if revokedInt == 1 {
		return fmt.Errorf("%w: certificate %s", ErrAlreadyRevoked, normSerial)
	}

	// Update certificate
	_, err = tx.ExecContext(ctx, "UPDATE certificates SET revoked = 1 WHERE serial = ?", normSerial)
	if err != nil {
		return err
	}

	// Insert revocation record
	_, err = tx.ExecContext(ctx, `
		INSERT INTO revocations (serial, revoked_at, reason)
		VALUES (?, ?, ?)
	`, normSerial, revokedAt.UTC(), reason)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetRevocation returns revocation details for a certificate.
func (s *SQLiteStorage) GetRevocation(ctx context.Context, serial string) (*RevocationRecord, error) {
	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return nil, fmt.Errorf("%w: empty serial number", ErrInvalidInput)
	}

	var rec RevocationRecord
	var revokedAt time.Time

	row := s.db.QueryRowContext(ctx, `
		SELECT serial, revoked_at, reason
		FROM revocations
		WHERE serial = ?
	`, normSerial)

	err := row.Scan(&rec.Serial, &revokedAt, &rec.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: revocation for serial %s", ErrNotFound, normSerial)
	}
	if err != nil {
		return nil, err
	}

	rec.RevokedAt = revokedAt.UTC()
	return &rec, nil
}

// ListRevoked returns all revoked certificate records ordered by revocation time.
func (s *SQLiteStorage) ListRevoked(ctx context.Context) ([]*RevocationRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT serial, revoked_at, reason
		FROM revocations
		ORDER BY revoked_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*RevocationRecord
	for rows.Next() {
		var rec RevocationRecord
		var revokedAt time.Time
		if err := rows.Scan(&rec.Serial, &revokedAt, &rec.Reason); err != nil {
			return nil, err
		}
		rec.RevokedAt = revokedAt.UTC()
		records = append(records, &rec)
	}

	return records, rows.Err()
}

// ReserveSerial idempotently registers a serial number to prevent collisions.
func (s *SQLiteStorage) ReserveSerial(ctx context.Context, serial string) error {
	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return fmt.Errorf("%w: empty serial number", ErrInvalidInput)
	}

	var exists int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM serials WHERE serial = ?", normSerial).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return fmt.Errorf("%w: serial %s already reserved", ErrAlreadyExists, normSerial)
	}

	_, err = s.db.ExecContext(ctx, "INSERT INTO serials (serial, issued_at) VALUES (?, ?)", normSerial, time.Now().UTC())
	return err
}

// Close closes the underlying database connection.
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}
