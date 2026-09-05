package storage_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"go-certa/pkg/storage"
)

func TestSaveAndGetCertificate(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	cert := &storage.CertificateRecord{
		Serial:    "01A2B3C4D5",
		Subject:   "CN=example.com,O=Acme Corp",
		Issuer:    "CN=Go-Certa Intermediate CA 1",
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		RawDER:    []byte{0x30, 0x82, 0x01, 0x0a},
		PEM:       []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
		Revoked:   false,
	}

	// 1. Save certificate
	if err := store.SaveCertificate(ctx, cert); err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// 2. Retrieve certificate
	retrieved, err := store.GetCertificate(ctx, "01a2b3c4d5")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if retrieved.Serial != "01a2b3c4d5" {
		t.Errorf("expected normalized serial '01a2b3c4d5', got %q", retrieved.Serial)
	}
	if retrieved.Subject != cert.Subject {
		t.Errorf("subject mismatch: got %q, want %q", retrieved.Subject, cert.Subject)
	}
	if retrieved.Issuer != cert.Issuer {
		t.Errorf("issuer mismatch: got %q, want %q", retrieved.Issuer, cert.Issuer)
	}
	if !retrieved.NotBefore.Equal(cert.NotBefore) {
		t.Errorf("NotBefore mismatch: got %v, want %v", retrieved.NotBefore, cert.NotBefore)
	}
	if !retrieved.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter mismatch: got %v, want %v", retrieved.NotAfter, cert.NotAfter)
	}
	if !bytes.Equal(retrieved.RawDER, cert.RawDER) {
		t.Errorf("RawDER mismatch: got %x, want %x", retrieved.RawDER, cert.RawDER)
	}
	if !bytes.Equal(retrieved.PEM, cert.PEM) {
		t.Errorf("PEM mismatch: got %s, want %s", retrieved.PEM, cert.PEM)
	}
	if retrieved.Revoked != false {
		t.Errorf("expected Revoked=false, got true")
	}

	// 3. Immutability check: mutating retrieved record should not mutate stored record
	retrieved.RawDER[0] = 0xFF
	retrieved2, err := store.GetCertificate(ctx, "01a2b3c4d5")
	if err != nil {
		t.Fatalf("second GetCertificate failed: %v", err)
	}
	if retrieved2.RawDER[0] == 0xFF {
		t.Fatal("Storage leaked internal slice mutable reference")
	}

	// 4. Duplicate serial insertion should fail
	dupErr := store.SaveCertificate(ctx, cert)
	if !errors.Is(dupErr, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists on duplicate save, got %v", dupErr)
	}
}

func TestSaveCertificateValidation(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	// Nil cert
	if err := store.SaveCertificate(ctx, nil); !errors.Is(err, storage.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for nil cert, got %v", err)
	}

	// Empty serial
	emptyCert := &storage.CertificateRecord{Serial: ""}
	if err := store.SaveCertificate(ctx, emptyCert); !errors.Is(err, storage.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for empty serial, got %v", err)
	}

	// Whitespace-only serial
	whitespaceCert := &storage.CertificateRecord{Serial: "   "}
	if err := store.SaveCertificate(ctx, whitespaceCert); !errors.Is(err, storage.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for whitespace serial, got %v", err)
	}
}

func TestGetCertificateNotFound(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	if _, err := store.GetCertificate(ctx, "nonexistent"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing cert, got %v", err)
	}

	if _, err := store.GetCertificate(ctx, ""); !errors.Is(err, storage.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for empty serial, got %v", err)
	}
}

func TestRevocationLifecycle(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	cert := &storage.CertificateRecord{
		Serial:  "deadbeef",
		Subject: "CN=victim.com",
		Issuer:  "CN=Go-Certa Intermediate CA 1",
	}
	if err := store.SaveCertificate(ctx, cert); err != nil {
		t.Fatalf("failed saving certificate: %v", err)
	}

	revTime := time.Now().UTC().Truncate(time.Second)
	reason := storage.ReasonKeyCompromise

	// 1. Revoke certificate
	if err := store.RevokeCertificate(ctx, "0xDEADBEEF", reason, revTime); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	// 2. Verify certificate record shows Revoked=true
	updatedCert, err := store.GetCertificate(ctx, "deadbeef")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if !updatedCert.Revoked {
		t.Errorf("expected certificate Revoked=true, got false")
	}

	// 3. Verify revocation record
	revRec, err := store.GetRevocation(ctx, "deadbeef")
	if err != nil {
		t.Fatalf("GetRevocation failed: %v", err)
	}
	if revRec.Serial != "deadbeef" {
		t.Errorf("expected serial 'deadbeef', got %q", revRec.Serial)
	}
	if revRec.Reason != reason {
		t.Errorf("expected reason %d, got %d", reason, revRec.Reason)
	}
	if !revRec.RevokedAt.Equal(revTime) {
		t.Errorf("RevokedAt mismatch: got %v, want %v", revRec.RevokedAt, revTime)
	}

	// 4. Double revocation should fail
	err = store.RevokeCertificate(ctx, "deadbeef", reason, revTime)
	if !errors.Is(err, storage.ErrAlreadyRevoked) {
		t.Fatalf("expected ErrAlreadyRevoked on repeated revocation, got %v", err)
	}

	// 5. Revoking non-existent certificate should return ErrNotFound
	err = store.RevokeCertificate(ctx, "123456", storage.ReasonUnspecified, revTime)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound revoking missing cert, got %v", err)
	}

	// 6. Get non-existent revocation
	if _, err := store.GetRevocation(ctx, "9999"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing revocation, got %v", err)
	}
}

func TestListRevoked(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	// Initially empty
	revokedList, err := store.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked failed: %v", err)
	}
	if len(revokedList) != 0 {
		t.Fatalf("expected 0 revoked certs, got %d", len(revokedList))
	}

	// Populate and revoke 3 certificates with staggered timestamps
	t0 := time.Now().UTC()
	serials := []string{"01", "02", "03"}
	for i, s := range serials {
		c := &storage.CertificateRecord{Serial: s, Subject: fmt.Sprintf("CN=host%d.com", i)}
		if err := store.SaveCertificate(ctx, c); err != nil {
			t.Fatalf("SaveCertificate failed: %v", err)
		}
		if err := store.RevokeCertificate(ctx, s, storage.ReasonAffiliationChanged, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	}

	list, err := store.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 revoked certs, got %d", len(list))
	}

	// Check order (should be sorted chronologically)
	if list[0].Serial != "01" || list[1].Serial != "02" || list[2].Serial != "03" {
		t.Fatalf("unexpected ordering: %s, %s, %s", list[0].Serial, list[1].Serial, list[2].Serial)
	}
}

func TestReserveSerial(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	serial := "cafe1234"

	// 1. Reserve serial
	if err := store.ReserveSerial(ctx, serial); err != nil {
		t.Fatalf("ReserveSerial failed: %v", err)
	}

	// 2. Duplicate reservation should fail (testing case normalization)
	if err := store.ReserveSerial(ctx, "0xCAFE1234"); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for already reserved serial, got %v", err)
	}

	// 3. Save certificate for the reserved serial should succeed
	cert := &storage.CertificateRecord{
		Serial:  serial,
		Subject: "CN=reserved.example.com",
	}
	if err := store.SaveCertificate(ctx, cert); err != nil {
		t.Fatalf("SaveCertificate for reserved serial failed: %v", err)
	}

	// 4. Reserve serial after cert already saved should fail
	if err := store.ReserveSerial(ctx, serial); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists reserving already issued cert serial, got %v", err)
	}

	// 5. Empty serial validation
	if err := store.ReserveSerial(ctx, ""); !errors.Is(err, storage.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput reserving empty serial, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	if err := store.SaveCertificate(ctx, &storage.CertificateRecord{Serial: "01"}); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on SaveCertificate, got %v", err)
	}
	if _, err := store.GetCertificate(ctx, "01"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on GetCertificate, got %v", err)
	}
	if err := store.RevokeCertificate(ctx, "01", 0, time.Now()); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on RevokeCertificate, got %v", err)
	}
	if _, err := store.GetRevocation(ctx, "01"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on GetRevocation, got %v", err)
	}
	if _, err := store.ListRevoked(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on ListRevoked, got %v", err)
	}
	if err := store.ReserveSerial(ctx, "01"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on ReserveSerial, got %v", err)
	}
}

func TestConcurrentOperations(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			serial := fmt.Sprintf("serial_%04d", workerID)

			// 1. Reserve serial
			if err := store.ReserveSerial(ctx, serial); err != nil {
				t.Errorf("worker %d ReserveSerial error: %v", workerID, err)
				return
			}

			// 2. Save certificate
			c := &storage.CertificateRecord{
				Serial:  serial,
				Subject: fmt.Sprintf("CN=host_%d.example.com", workerID),
				RawDER:  []byte{byte(workerID)},
			}
			if err := store.SaveCertificate(ctx, c); err != nil {
				t.Errorf("worker %d SaveCertificate error: %v", workerID, err)
				return
			}

			// 3. Get certificate
			retrieved, err := store.GetCertificate(ctx, serial)
			if err != nil {
				t.Errorf("worker %d GetCertificate error: %v", workerID, err)
				return
			}
			if retrieved.Subject != c.Subject {
				t.Errorf("worker %d subject mismatch: %q vs %q", workerID, retrieved.Subject, c.Subject)
			}

			// 4. Even workers revoke their certificate
			if workerID%2 == 0 {
				if err := store.RevokeCertificate(ctx, serial, storage.ReasonSuperseded, time.Now().UTC()); err != nil {
					t.Errorf("worker %d RevokeCertificate error: %v", workerID, err)
					return
				}

				if _, err := store.GetRevocation(ctx, serial); err != nil {
					t.Errorf("worker %d GetRevocation error: %v", workerID, err)
					return
				}
			}

			// 5. Query ListRevoked
			if _, err := store.ListRevoked(ctx); err != nil {
				t.Errorf("worker %d ListRevoked error: %v", workerID, err)
				return
			}
		}()
	}

	wg.Wait()

	// Verify count of revoked certificates
	revoked, err := store.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked failed: %v", err)
	}
	expectedRevoked := workers / 2
	if len(revoked) != expectedRevoked {
		t.Fatalf("expected %d revoked certificates, got %d", expectedRevoked, len(revoked))
	}
}
