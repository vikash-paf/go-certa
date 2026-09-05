package audit_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"go-certa/pkg/audit"
)

func TestChainAuditLogger_NormalFlow(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewChainAuditLogger(&buf)

	ctx := context.Background()

	// 1. Log genesis event
	evt1, err := logger.LogEvent(ctx, audit.ActionKeyAccess, "ca-daemon", "HSM_Slot_0", audit.StatusSuccess, map[string]string{
		"mechanism": "PKCS#11",
	})
	if err != nil {
		t.Fatalf("unexpected error logging event 1: %v", err)
	}

	if evt1.PrevHash != audit.GenesisHash {
		t.Errorf("expected genesis prev_hash %s, got %s", audit.GenesisHash, evt1.PrevHash)
	}
	if evt1.Hash == "" {
		t.Errorf("empty hash on event 1")
	}

	// 2. Log second event
	evt2, err := logger.LogEvent(ctx, audit.ActionCertSign, "est-worker", "serial_0123456789abcdef", audit.StatusSuccess, map[string]string{
		"profile": "server-tls",
		"cn":      "api.internal.network",
	})
	if err != nil {
		t.Fatalf("unexpected error logging event 2: %v", err)
	}

	if evt2.PrevHash != evt1.Hash {
		t.Errorf("expected event 2 prev_hash to match event 1 hash (%s), got %s", evt1.Hash, evt2.PrevHash)
	}

	// 3. Log third event (rejection)
	evt3, err := logger.LogEvent(ctx, audit.ActionPolicyReject, "acme-service", "*.example.com", audit.StatusFailure, map[string]string{
		"reason": "forbidden_apex_wildcard",
	})
	if err != nil {
		t.Fatalf("unexpected error logging event 3: %v", err)
	}

	if evt3.PrevHash != evt2.Hash {
		t.Errorf("expected event 3 prev_hash to match event 2 hash (%s), got %s", evt2.Hash, evt3.PrevHash)
	}

	// 4. Verify entire chain
	valid, err := logger.VerifyChain()
	if err != nil || !valid {
		t.Fatalf("expected valid chain, got valid=%v, err=%v", valid, err)
	}

	if logger.EventCount() != 3 {
		t.Errorf("expected 3 events, got %d", logger.EventCount())
	}

	// 5. Check streaming buffer received 3 JSON lines
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Errorf("expected 3 streamed lines, got %d", len(lines))
	}
}

func TestChainAuditLogger_TamperDetection(t *testing.T) {
	ctx := context.Background()

	t.Run("tampered event status", func(t *testing.T) {
		logger := audit.NewChainAuditLogger()
		_, _ = logger.LogEvent(ctx, audit.ActionCertSign, "admin", "serial1", audit.StatusSuccess, nil)
		_, _ = logger.LogEvent(ctx, audit.ActionCertRevoke, "admin", "serial1", audit.StatusSuccess, nil)

		events := logger.Events()
		// Tamper with second event in-place through pointer
		events[1].Status = audit.StatusFailure

		valid, err := logger.VerifyChain()
		if valid || err == nil {
			t.Errorf("expected tamper detection error, got valid=%v, err=%v", valid, err)
		}
	})

	t.Run("tampered previous hash linkage", func(t *testing.T) {
		logger := audit.NewChainAuditLogger()
		_, _ = logger.LogEvent(ctx, audit.ActionKeyAccess, "hsm", "slot0", audit.StatusSuccess, nil)
		_, _ = logger.LogEvent(ctx, audit.ActionCertSign, "ca", "serial1", audit.StatusSuccess, nil)

		events := logger.Events()
		// Tamper with PrevHash of event 1
		events[1].PrevHash = "deadbeef"

		valid, err := logger.VerifyChain()
		if valid || err == nil {
			t.Errorf("expected prev_hash mismatch error, got valid=%v, err=%v", valid, err)
		}
	})

	t.Run("hash modification", func(t *testing.T) {
		logger := audit.NewChainAuditLogger()
		evt1, _ := logger.LogEvent(ctx, audit.ActionKeyAccess, "hsm", "slot0", audit.StatusSuccess, nil)
		_, _ = logger.LogEvent(ctx, audit.ActionCertSign, "ca", "serial1", audit.StatusSuccess, nil)

		// Check that ComputeEventHash accurately matches recorded hash
		if audit.ComputeEventHash(evt1) != evt1.Hash {
			t.Errorf("computed hash mismatch")
		}

		// Mutate copy
		evt1Copy := *evt1
		evt1Copy.Resource = "malicious_slot"
		if audit.ComputeEventHash(&evt1Copy) == evt1.Hash {
			t.Errorf("expected hash collision to not occur")
		}
	})
}

func TestChainAuditLogger_EmptyChain(t *testing.T) {
	logger := audit.NewChainAuditLogger()
	valid, err := logger.VerifyChain()
	if err != nil || !valid {
		t.Fatalf("empty chain must be valid, got valid=%v, err=%v", valid, err)
	}
	if len(logger.Events()) != 0 {
		t.Errorf("expected 0 events")
	}
}

func TestChainAuditLogger_ConcurrentLogging(t *testing.T) {
	logger := audit.NewChainAuditLogger()
	ctx := context.Background()

	var wg sync.WaitGroup
	workers := 20
	eventsPerWorker := 25

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				_, err := logger.LogEvent(ctx, audit.ActionCertSign, fmt.Sprintf("worker-%d", workerID),
					fmt.Sprintf("serial-%d-%d", workerID, i), audit.StatusSuccess, map[string]string{
						"worker": fmt.Sprintf("%d", workerID),
					})
				if err != nil {
					t.Errorf("concurrent LogEvent failed: %v", err)
				}
			}
		}(w)
	}

	wg.Wait()

	totalExpected := workers * eventsPerWorker
	if logger.EventCount() != totalExpected {
		t.Fatalf("expected %d events, got %d", totalExpected, logger.EventCount())
	}

	// Verify cryptographic integrity of concurrently logged chain
	valid, err := logger.VerifyChain()
	if err != nil || !valid {
		t.Fatalf("concurrent chain verification failed: %v", err)
	}
}
