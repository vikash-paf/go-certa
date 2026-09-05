package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Standard Audit Actions
const (
	ActionCertSign     = "CERT_SIGN"
	ActionCertRevoke   = "CERT_REVOKE"
	ActionCRLIssue     = "CRL_ISSUE"
	ActionKeyAccess    = "KEY_ACCESS"
	ActionPolicyReject = "POLICY_REJECT"
)

// Standard Audit Statuses
const (
	StatusSuccess = "SUCCESS"
	StatusFailure = "FAILURE"
)

// GenesisHash represents the initial SHA-256 hash seed for the chain (64 hex zeroes).
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	// ErrNilEvent is returned when attempting to process a nil audit event.
	ErrNilEvent = errors.New("audit event cannot be nil")

	// ErrChainTampered is returned when hash chain validation detects tampering.
	ErrChainTampered = errors.New("audit chain integrity verification failed")
)

// AuditEvent represents a single cryptographically signed, tamper-evident log entry.
type AuditEvent struct {
	EventID   string            `json:"event_id"`
	Timestamp time.Time         `json:"timestamp"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor"`
	Resource  string            `json:"resource"`
	Status    string            `json:"status"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// ComputeEventHash computes the deterministic SHA-256 digest of an event and its PrevHash.
func ComputeEventHash(event *AuditEvent) string {
	if event == nil {
		return ""
	}

	canonicalMeta := canonicalMetadata(event.Metadata)
	canonicalStr := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		event.EventID,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.Action,
		event.Actor,
		event.Resource,
		event.Status,
		canonicalMeta,
		event.PrevHash,
	)

	sum := sha256.Sum256([]byte(canonicalStr))
	return hex.EncodeToString(sum[:])
}

func canonicalMetadata(meta map[string]string) string {
	if len(meta) == 0 {
		return ""
	}

	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(meta[k])
	}
	return sb.String()
}

// AuditLogger defines the interface for emitting and verifying audit log records.
type AuditLogger interface {
	LogEvent(ctx context.Context, action, actor, resource, status string, metadata map[string]string) (*AuditEvent, error)
	VerifyChain() (bool, error)
	Events() []*AuditEvent
	EventCount() int
}

// ChainAuditLogger implements an append-only, thread-safe, cryptographically chained audit logger.
type ChainAuditLogger struct {
	mu       sync.RWMutex
	events   []*AuditEvent
	lastHash string
	writer   io.Writer
}

// NewChainAuditLogger initializes a new cryptographic hash-chain audit logger.
// If an io.Writer is provided (e.g. os.Stdout or a log file), JSON records will be streamed upon emission.
func NewChainAuditLogger(writers ...io.Writer) *ChainAuditLogger {
	var w io.Writer
	if len(writers) > 0 && writers[0] != nil {
		w = io.MultiWriter(writers...)
	}

	return &ChainAuditLogger{
		events:   make([]*AuditEvent, 0),
		lastHash: GenesisHash,
		writer:   w,
	}
}

// LogEvent records a new event, cryptographically links it to the previous event, and appends it to the chain.
func (l *ChainAuditLogger) LogEvent(
	ctx context.Context,
	action, actor, resource, status string,
	metadata map[string]string,
) (*AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 1. Generate unique random event ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed generating event id: %w", err)
	}
	eventID := fmt.Sprintf("evt_%s", hex.EncodeToString(idBytes))

	// 2. Clone metadata
	metaCopy := make(map[string]string, len(metadata))
	for k, v := range metadata {
		metaCopy[k] = v
	}

	event := &AuditEvent{
		EventID:   eventID,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Actor:     actor,
		Resource:  resource,
		Status:    status,
		Metadata:  metaCopy,
		PrevHash:  l.lastHash,
	}

	// 3. Compute deterministic hash over event fields + PrevHash
	event.Hash = ComputeEventHash(event)

	// 4. Append to in-memory chain and update head hash
	l.events = append(l.events, event)
	l.lastHash = event.Hash

	// 5. Optional durable stream write
	if l.writer != nil {
		data, err := json.Marshal(event)
		if err == nil {
			data = append(data, '\n')
			_, _ = l.writer.Write(data)
		}
	}

	return event, nil
}

// VerifyChain verifies the cryptographic integrity of the entire audit chain from genesis to head.
// Returns (true, nil) if the chain is intact, or (false, error) specifying the exact index and tamper point.
func (l *ChainAuditLogger) VerifyChain() (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	expectedPrev := GenesisHash
	for i, evt := range l.events {
		if evt == nil {
			return false, fmt.Errorf("%w: nil event at index %d", ErrChainTampered, i)
		}

		// Verify linkage to previous event hash
		if evt.PrevHash != expectedPrev {
			return false, fmt.Errorf("%w: prev_hash mismatch at index %d (event %s): expected %s, got %s",
				ErrChainTampered, i, evt.EventID, expectedPrev, evt.PrevHash)
		}

		// Recompute event hash from raw fields
		recomputed := ComputeEventHash(evt)
		if evt.Hash != recomputed {
			return false, fmt.Errorf("%w: hash mismatch at index %d (event %s): expected %s, got %s",
				ErrChainTampered, i, evt.EventID, recomputed, evt.Hash)
		}

		expectedPrev = evt.Hash
	}

	return true, nil
}

// Events returns a copy of the recorded audit events.
func (l *ChainAuditLogger) Events() []*AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	cpy := make([]*AuditEvent, len(l.events))
	copy(cpy, l.events)
	return cpy
}

// EventCount returns the current number of events in the chain.
func (l *ChainAuditLogger) EventCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.events)
}
