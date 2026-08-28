// Package crypto composes Go standard library crypto primitives into the
// building blocks ZeroVault needs: PBKDF2 key derivation, AES-256-GCM
// authenticated encryption, and secure random generation. No cryptographic
// algorithm is implemented from scratch here — only composition of
// crypto/aes, crypto/cipher, crypto/hmac, crypto/sha256, and crypto/rand.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const (
	// PBKDF2Iterations is the iteration count used for vault master-key
	// derivation. 100,000 rounds of HMAC-SHA256 balances brute-force
	// resistance against acceptable unlock latency on commodity hardware.
	PBKDF2Iterations = 100_000
	// PBKDF2KeyLen is the derived key length in bytes (AES-256 key size).
	PBKDF2KeyLen = 32
	// SaltLen is the random salt length stored alongside each vault.
	SaltLen = 16
)

// DeriveKey derives a 32-byte AES-256 key from a password and salt using
// PBKDF2-HMAC-SHA256 with PBKDF2Iterations rounds.
func DeriveKey(password, salt []byte) []byte {
	return PBKDF2(password, salt, PBKDF2Iterations, PBKDF2KeyLen, sha256.New)
}

// PBKDF2 implements RFC 8018 (PKCS #5 v2.1) password-based key derivation,
// generic over the underlying HMAC hash constructor. It is built entirely
// from crypto/hmac; the algorithm itself (the F/T-block construction) is
// standard and specified by the RFC, not a custom crypto primitive.
func PBKDF2(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hLen := prf.Size()

	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	var buf [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf[:], uint32(block))

		prf.Reset()
		prf.Write(salt)
		prf.Write(buf[:])
		u := prf.Sum(nil)

		t := make([]byte, hLen)
		copy(t, u)

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}

		dk = append(dk, t...)
	}

	return dk[:keyLen]
}
