package crypto

import (
	"strings"
	"testing"
)

func TestRandomBytes_Length(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("got %d bytes, want 32", len(b))
	}
}

func TestRandomBytes_NotAllZero(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("RandomBytes returned all zero bytes (suspicious)")
	}
}

func TestGeneratePassword_Length(t *testing.T) {
	pw, err := GeneratePassword(PasswordOptions{Length: 20, Lower: true, Upper: true, Digits: true, Symbols: true})
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if len(pw) != 20 {
		t.Fatalf("got length %d, want 20", len(pw))
	}
}

func TestGeneratePassword_RespectsCharsetOnly(t *testing.T) {
	pw, err := GeneratePassword(PasswordOptions{Length: 200, Digits: true})
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if strings.Trim(pw, charsDigits) != "" {
		t.Fatalf("digits-only password contained non-digit characters: %q", pw)
	}
}

func TestGeneratePassword_NoClassSelectedErrors(t *testing.T) {
	if _, err := GeneratePassword(PasswordOptions{Length: 10}); err == nil {
		t.Fatalf("expected error when no character class is enabled")
	}
}

func TestGeneratePassword_ZeroLengthErrors(t *testing.T) {
	if _, err := GeneratePassword(PasswordOptions{Length: 0, Lower: true}); err == nil {
		t.Fatalf("expected error for zero length")
	}
}
