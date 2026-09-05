package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStorage_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	store, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed creating sqlite storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Reserve serial
	serial := "01a2b3c4d5"
	if err := store.ReserveSerial(ctx, serial); err != nil {
		t.Fatalf("ReserveSerial failed: %v", err)
	}

	// Double reserve should fail with ErrAlreadyExists
	if err := store.ReserveSerial(ctx, serial); err == nil {
		t.Fatalf("expected error on duplicate ReserveSerial")
	}

	// 2. Save certificate
	now := time.Now().Truncate(time.Second)
	cert := &CertificateRecord{
		Serial:    serial,
		Subject:   "CN=test.example.com",
		Issuer:    "CN=Go-Certa Intermediate",
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
		RawDER:    []byte("dummy-der"),
		PEM:       []byte("dummy-pem"),
		Revoked:   false,
	}

	if err := store.SaveCertificate(ctx, cert); err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// 3. Retrieve certificate
	fetched, err := store.GetCertificate(ctx, serial)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if fetched.Subject != cert.Subject || fetched.Revoked != false {
		t.Fatalf("mismatched cert fields: %+v", fetched)
	}

	// 4. Revoke certificate
	revTime := time.Now().Truncate(time.Second)
	if err := store.RevokeCertificate(ctx, serial, 1, revTime); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	// Re-query certificate to ensure revoked flag is updated
	fetched, err = store.GetCertificate(ctx, serial)
	if err != nil {
		t.Fatalf("GetCertificate after revocation failed: %v", err)
	}
	if !fetched.Revoked {
		t.Fatalf("expected cert to be revoked")
	}

	// 5. Query revocation record
	revRec, err := store.GetRevocation(ctx, serial)
	if err != nil {
		t.Fatalf("GetRevocation failed: %v", err)
	}
	if revRec.Reason != 1 {
		t.Fatalf("expected reason 1, got %d", revRec.Reason)
	}

	// 6. List revoked
	list, err := store.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked failed: %v", err)
	}
	if len(list) != 1 || list[0].Serial != serial {
		t.Fatalf("unexpected revoked list: %+v", list)
	}
}
