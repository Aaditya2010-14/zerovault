package totp

import (
	"bytes"
	"testing"
)

func TestDecodeSecret_StandardBase32(t *testing.T) {
	// "Hello!" base32-encoded with standard padding.
	got, err := DecodeSecret("JBSWY3DPEE======")
	if err != nil {
		t.Fatalf("DecodeSecret: %v", err)
	}
	if string(got) != "Hello!" {
		t.Fatalf("DecodeSecret = %q, want %q", got, "Hello!")
	}
}

func TestDecodeSecret_TolerantOfLowercaseSpacesAndMissingPadding(t *testing.T) {
	got, err := DecodeSecret("jbsw y3dp ee")
	if err != nil {
		t.Fatalf("DecodeSecret: %v", err)
	}
	if string(got) != "Hello!" {
		t.Fatalf("DecodeSecret = %q, want %q", got, "Hello!")
	}
}

func TestDecodeSecret_EmptyFails(t *testing.T) {
	if _, err := DecodeSecret(""); err == nil {
		t.Fatalf("expected error for empty secret")
	}
}

func TestDecodeSecret_InvalidCharsFails(t *testing.T) {
	if _, err := DecodeSecret("not-valid-base32!!!"); err == nil {
		t.Fatalf("expected error for invalid base32 input")
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdefghij") // 20 bytes
	encoded := EncodeSecret(key)
	decoded, err := DecodeSecret(encoded)
	if err != nil {
		t.Fatalf("DecodeSecret: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatalf("round trip mismatch: got %q, want %q", decoded, key)
	}
}

func TestGenerateSecret_LengthAndDecodable(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	key, err := DecodeSecret(secret)
	if err != nil {
		t.Fatalf("DecodeSecret(generated secret): %v", err)
	}
	if len(key) != SecretLen {
		t.Fatalf("decoded generated secret has %d bytes, want %d", len(key), SecretLen)
	}
}

func TestGenerateSecret_Unique(t *testing.T) {
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	s2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if s1 == s2 {
		t.Fatalf("two calls to GenerateSecret produced the same secret")
	}
}
