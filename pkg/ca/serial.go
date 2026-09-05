package ca

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"go-certa/pkg/storage"
)

const (
	// MinSerialBits is the minimum entropy required by CA/Browser Forum BR §7.1 (64 bits).
	MinSerialBits = 64

	// MaxSerialBits is the maximum bit length ensuring a positive ASN.1 integer fits within 20 octets (159 bits).
	MaxSerialBits = 159

	// DefaultSerialBits is the default entropy bit length (128 bits / 16 octets).
	DefaultSerialBits = 128

	// MaxReservationRetries is the maximum attempts to find an unallocated serial number.
	MaxReservationRetries = 5
)

var (
	// ErrInvalidSerialBits indicates the requested bit length is outside the [64, 159] bit window.
	ErrInvalidSerialBits = errors.New("serial bit length must be between 64 and 159 bits")

	// ErrSerialExhaustion indicates collision retries failed to find a unique serial number.
	ErrSerialExhaustion = errors.New("failed to reserve unique serial number after maximum retries")
)

// GenerateSerial generates a cryptographically secure random positive serial number with DefaultSerialBits (128 bits).
func GenerateSerial() (*big.Int, error) {
	return GenerateSerialWithBits(DefaultSerialBits)
}

// GenerateSerialWithBits generates a cryptographically secure random positive serial number with the specified bit length.
// The resulting integer is strictly positive (> 0) and contains 'bits' bits of CSPRNG entropy.
func GenerateSerialWithBits(bits int) (*big.Int, error) {
	if bits < MinSerialBits || bits > MaxSerialBits {
		return nil, fmt.Errorf("%w: requested %d", ErrInvalidSerialBits, bits)
	}

	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	for {
		serial, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("failed reading random entropy: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// FormatSerial converts a big.Int serial number to a canonical lowercase hexadecimal string.
func FormatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return strings.ToLower(serial.Text(16))
}

// ParseSerial parses a hexadecimal serial string into a positive *big.Int.
func ParseSerial(hexStr string) (*big.Int, error) {
	cleaned := storage.NormalizeSerial(hexStr)
	if cleaned == "" {
		return nil, errors.New("empty serial string")
	}
	serial, ok := new(big.Int).SetString(cleaned, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hexadecimal serial string: %q", hexStr)
	}
	if serial.Sign() <= 0 {
		return nil, errors.New("serial number must be positive")
	}
	return serial, nil
}

// GenerateAndReserveSerial generates a serial number with DefaultSerialBits and reserves it in the provided Storage.
func GenerateAndReserveSerial(ctx context.Context, store storage.Storage) (*big.Int, error) {
	return GenerateAndReserveSerialWithBits(ctx, store, DefaultSerialBits)
}

// GenerateAndReserveSerialWithBits generates a serial number with the requested bit length and reserves it in the provided Storage.
func GenerateAndReserveSerialWithBits(ctx context.Context, store storage.Storage, bits int) (*big.Int, error) {
	if store == nil {
		return nil, errors.New("storage cannot be nil")
	}

	for attempt := 0; attempt < MaxReservationRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		serial, err := GenerateSerialWithBits(bits)
		if err != nil {
			return nil, err
		}

		serialHex := FormatSerial(serial)
		err = store.ReserveSerial(ctx, serialHex)
		if err == nil {
			return serial, nil
		}

		if errors.Is(err, storage.ErrAlreadyExists) {
			// Entropy collision occurred (astronomically rare with >= 64 bits), retry
			continue
		}

		return nil, fmt.Errorf("failed reserving serial %s: %w", serialHex, err)
	}

	return nil, ErrSerialExhaustion
}
