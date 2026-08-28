package crypto

import (
	"crypto/rand"
	"fmt"
)

// Character sets available for generated passwords.
const (
	charsLower   = "abcdefghijklmnopqrstuvwxyz"
	charsUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsDigits  = "0123456789"
	charsSymbols = "!@#$%^&*()-_=+[]{}<>?/.,~"
)

// PasswordOptions controls character classes included in a generated
// password. At least one class must be enabled.
type PasswordOptions struct {
	Length  int
	Upper   bool
	Lower   bool
	Digits  bool
	Symbols bool
}

// RandomBytes returns n cryptographically secure random bytes read from
// crypto/rand. math/rand must never be used for anything security-relevant.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: failed to read random bytes: %w", err)
	}
	return b, nil
}

// RandomSalt returns a new SaltLen-byte cryptographically secure salt.
func RandomSalt() ([]byte, error) {
	return RandomBytes(SaltLen)
}

// GeneratePassword produces a random password drawn uniformly from the
// requested character classes using crypto/rand for every character choice
// (rejection sampling avoids modulo bias).
func GeneratePassword(opts PasswordOptions) (string, error) {
	if opts.Length <= 0 {
		return "", fmt.Errorf("crypto: password length must be positive, got %d", opts.Length)
	}

	var alphabet string
	if opts.Lower {
		alphabet += charsLower
	}
	if opts.Upper {
		alphabet += charsUpper
	}
	if opts.Digits {
		alphabet += charsDigits
	}
	if opts.Symbols {
		alphabet += charsSymbols
	}
	if alphabet == "" {
		return "", fmt.Errorf("crypto: at least one character class must be enabled")
	}

	result := make([]byte, opts.Length)
	for i := range result {
		idx, err := randomIndex(len(alphabet))
		if err != nil {
			return "", err
		}
		result[i] = alphabet[idx]
	}
	return string(result), nil
}

// randomIndex returns a uniformly distributed random index in [0, n) using
// rejection sampling against crypto/rand, avoiding the modulo bias that a
// naive `randomByte() % n` would introduce.
func randomIndex(n int) (int, error) {
	if n <= 0 || n > 256 {
		return 0, fmt.Errorf("crypto: randomIndex range out of bounds: %d", n)
	}
	// Largest multiple of n that fits in a byte; values >= this are
	// rejected and re-drawn so every valid index has equal probability.
	limit := 256 - (256 % n)
	buf := make([]byte, 1)
	for {
		if _, err := rand.Read(buf); err != nil {
			return 0, fmt.Errorf("crypto: failed to read random byte: %w", err)
		}
		if int(buf[0]) < limit {
			return int(buf[0]) % n, nil
		}
	}
}
