package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

// powersOf10 avoids repeated math.Pow calls for the small set of valid
// digit counts.
var powersOf10 = [...]uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000}

// GenerateHOTP implements RFC 4226 HOTP: HMAC-SHA1(key, counter) followed by
// dynamic truncation and a modulo reduction to `digits` decimal digits.
// TOTP requires SHA-1 here (RFC 6238), not SHA-256 — this is not a choice,
// it's what the RFC and every compatible authenticator app expect.
func GenerateHOTP(key []byte, counter uint64, digits int) (string, error) {
	if digits < 6 || digits > 10 {
		return "", fmt.Errorf("totp: digits must be between 6 and 10, got %d", digits)
	}

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 section 5.3: take the low nibble of
	// the last byte as an offset, then read 4 bytes from there as a
	// big-endian uint32 with the top bit masked off.
	offset := sum[len(sum)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF

	code := truncated % powersOf10[digits]
	return fmt.Sprintf("%0*d", digits, code), nil
}
