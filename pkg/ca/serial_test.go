package ca_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"

	"go-certa/pkg/ca"
	"go-certa/pkg/storage"
)

func TestGenerateSerial_Properties(t *testing.T) {
	for i := 0; i < 100; i++ {
		serial, err := ca.GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial failed: %v", err)
		}

		// 1. Must be strictly positive integer (RFC 5280 §4.1.2.2)
		if serial.Sign() <= 0 {
			t.Fatalf("expected positive serial number, got %v", serial)
		}

		// 2. ASN.1 DER 20-octet limit requires maximum 159 bits
		if serial.BitLen() > ca.MaxSerialBits {
			t.Fatalf("serial bit length %d exceeds max %d", serial.BitLen(), ca.MaxSerialBits)
		}

		// 3. Default bits is 128, bit length should be close to 128 (typically 125-128)
		if serial.BitLen() < 64 {
			t.Fatalf("serial bit length %d is less than CABF minimum 64 bits", serial.BitLen())
		}
	}
}

func TestGenerateSerialWithBits_Bounds(t *testing.T) {
	// Valid bit lengths
	validBits := []int{ca.MinSerialBits, 96, 128, ca.MaxSerialBits}
	for _, b := range validBits {
		s, err := ca.GenerateSerialWithBits(b)
		if err != nil {
			t.Fatalf("GenerateSerialWithBits(%d) failed: %v", b, err)
		}
		if s.Sign() <= 0 {
			t.Fatalf("expected positive serial for %d bits, got %v", b, s)
		}
		if s.BitLen() > b {
			t.Fatalf("serial bit length %d exceeds requested bits %d", s.BitLen(), b)
		}
	}

	// Invalid bit lengths
	invalidBits := []int{-10, 0, 1, 32, 63, 160, 256}
	for _, b := range invalidBits {
		_, err := ca.GenerateSerialWithBits(b)
		if !errors.Is(err, ca.ErrInvalidSerialBits) {
			t.Fatalf("expected ErrInvalidSerialBits for %d bits, got %v", b, err)
		}
	}
}

func TestSerialUniqueness_Bulk(t *testing.T) {
	const count = 10000
	seen := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		serial, err := ca.GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial failed at iteration %d: %v", i, err)
		}

		hexStr := ca.FormatSerial(serial)
		if _, exists := seen[hexStr]; exists {
			t.Fatalf("collision detected for serial %s at iteration %d", hexStr, i)
		}
		seen[hexStr] = struct{}{}
	}
}

func TestFormatAndParseSerial(t *testing.T) {
	testVal := big.NewInt(123456789)
	hexStr := ca.FormatSerial(testVal)
	if hexStr != "75bcd15" {
		t.Fatalf("expected hex '75bcd15', got %q", hexStr)
	}

	// Parse valid serials
	parsed, err := ca.ParseSerial(hexStr)
	if err != nil {
		t.Fatalf("ParseSerial failed: %v", err)
	}
	if parsed.Cmp(testVal) != 0 {
		t.Fatalf("parsed value %v does not match original %v", parsed, testVal)
	}

	// Parse with 0x prefix and uppercase
	parsedPrefix, err := ca.ParseSerial("0x75BCD15")
	if err != nil {
		t.Fatalf("ParseSerial with prefix failed: %v", err)
	}
	if parsedPrefix.Cmp(testVal) != 0 {
		t.Fatalf("parsed prefixed value %v does not match original %v", parsedPrefix, testVal)
	}

	// Nil format
	if ca.FormatSerial(nil) != "" {
		t.Fatalf("expected empty string for nil serial")
	}

	// Invalid parse inputs
	invalidInputs := []string{"", "   ", "not-a-hex", "0", "0x0", "-5"}
	for _, inv := range invalidInputs {
		if _, err := ca.ParseSerial(inv); err == nil {
			t.Fatalf("expected error parsing invalid serial %q, got nil", inv)
		}
	}
}

func TestGenerateAndReserveSerial(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	// 1. Generate and reserve
	serial, err := ca.GenerateAndReserveSerial(ctx, store)
	if err != nil {
		t.Fatalf("GenerateAndReserveSerial failed: %v", err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("invalid generated serial: %v", serial)
	}

	// 2. Serial should already be reserved in store
	hexStr := ca.FormatSerial(serial)
	if err := store.ReserveSerial(ctx, hexStr); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists when re-reserving %s, got %v", hexStr, err)
	}

	// 3. Nil store should error
	if _, err := ca.GenerateAndReserveSerial(ctx, nil); err == nil {
		t.Fatalf("expected error when store is nil")
	}

	// 4. Cancelled context
	cancCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ca.GenerateAndReserveSerial(cancCtx, store); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestConcurrentGenerateAndReserveSerial(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	const routines = 100
	var wg sync.WaitGroup
	wg.Add(routines)

	serials := make([]*big.Int, routines)
	errs := make([]error, routines)

	for i := 0; i < routines; i++ {
		idx := i
		go func() {
			defer wg.Done()
			s, err := ca.GenerateAndReserveSerial(ctx, store)
			serials[idx] = s
			errs[idx] = err
		}()
	}

	wg.Wait()

	seen := make(map[string]struct{}, routines)
	for i := 0; i < routines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		hexStr := ca.FormatSerial(serials[i])
		if _, exists := seen[hexStr]; exists {
			t.Fatalf("duplicate serial found: %s", hexStr)
		}
		seen[hexStr] = struct{}{}
	}
}
