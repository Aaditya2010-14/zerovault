package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// NonceLen is the standard GCM nonce length in bytes.
const NonceLen = 12

// Encrypt seals plaintext under a 32-byte AES-256 key using AES-GCM with a
// freshly generated random nonce. The nonce is never reused across saves —
// it is drawn fresh from crypto/rand on every call. The returned ciphertext
// has the nonce prepended: nonce(12) || ciphertext || tag(16).
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM mode: %w", err)
	}

	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	// Seal appends the ciphertext+tag to the nonce, producing
	// nonce || ciphertext || tag in one contiguous slice.
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}

// Decrypt opens ciphertext produced by Encrypt, verifying the GCM
// authentication tag. It returns an error if the key is wrong, the data was
// tampered with, or the input is malformed — GCM's tag check makes these
// indistinguishable, which is intentional (no oracle for attackers).
func Decrypt(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}

	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed (wrong password or corrupted data)")
	}
	return plaintext, nil
}
