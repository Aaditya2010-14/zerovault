// Package totp implements HOTP (RFC 4226) and TOTP (RFC 6238) one-time
// password generation compatible with Google Authenticator and similar
// apps, built entirely from crypto/hmac, crypto/sha1, and encoding/base32.
package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// SecretLen is the byte length of newly generated TOTP secrets (160 bits,
// matching the RFC 4226 recommended HMAC-SHA1 key size).
const SecretLen = 20

// DecodeSecret decodes a user-supplied Base32 secret (as shown by Google
// Authenticator setup screens) into raw key bytes. It tolerates the
// formatting quirks real secrets come in: lowercase letters, embedded
// spaces, and missing "=" padding.
func DecodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if normalized == "" {
		return nil, fmt.Errorf("totp: secret cannot be empty")
	}

	// encoding/base32 requires correct padding; pad out to a multiple of 8.
	if rem := len(normalized) % 8; rem != 0 {
		normalized += strings.Repeat("=", 8-rem)
	}

	key, err := base32.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("totp: invalid base32 secret: %w", err)
	}
	return key, nil
}

// EncodeSecret encodes raw key bytes as an unpadded Base32 string, the
// conventional format for displaying/provisioning TOTP secrets.
func EncodeSecret(key []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// GenerateSecret returns a new random SecretLen-byte TOTP secret, Base32
// encoded, drawn from crypto/rand.
func GenerateSecret() (string, error) {
	key := make([]byte, SecretLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("totp: failed to generate secret: %w", err)
	}
	return EncodeSecret(key), nil
}
