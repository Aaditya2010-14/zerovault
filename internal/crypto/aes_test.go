package crypto

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := RandomBytes(PBKDF2KeyLen)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return key
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	sealed, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(key, sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncrypt_NonceUniquePerCall(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same plaintext every time")

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		sealed, err := Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		nonce := string(sealed[:NonceLen])
		if seen[nonce] {
			t.Fatalf("nonce reused across Encrypt calls: %x", nonce)
		}
		seen[nonce] = true
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	key := testKey(t)
	wrongKey := testKey(t)

	sealed, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(wrongKey, sealed); err == nil {
		t.Fatalf("Decrypt succeeded with wrong key, want error")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	key := testKey(t)

	sealed, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatalf("Decrypt succeeded on tampered ciphertext, want auth failure")
	}
}

func TestDecrypt_TruncatedInputFails(t *testing.T) {
	key := testKey(t)
	if _, err := Decrypt(key, []byte("short")); err == nil {
		t.Fatalf("Decrypt succeeded on truncated input, want error")
	}
}
