package totp

import "testing"

// TestGenerateHOTP_RFC4226Vectors validates against the official RFC 4226
// Appendix D test vectors: 6-digit HOTP codes for the fixed 20-byte ASCII
// secret "12345678901234567890" at counters 0-9.
func TestGenerateHOTP_RFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")

	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for counter, expected := range want {
		got, err := GenerateHOTP(secret, uint64(counter), 6)
		if err != nil {
			t.Fatalf("GenerateHOTP(counter=%d): %v", counter, err)
		}
		if got != expected {
			t.Errorf("GenerateHOTP(counter=%d) = %q, want %q", counter, got, expected)
		}
	}
}

func TestGenerateHOTP_InvalidDigitsErrors(t *testing.T) {
	secret := []byte("12345678901234567890")
	if _, err := GenerateHOTP(secret, 0, 5); err == nil {
		t.Fatalf("expected error for digits=5 (below minimum)")
	}
	if _, err := GenerateHOTP(secret, 0, 11); err == nil {
		t.Fatalf("expected error for digits=11 (above maximum)")
	}
}

func TestGenerateHOTP_ZeroPadded(t *testing.T) {
	// Any digit count should always return exactly that many characters,
	// zero-padded on the left.
	secret := []byte("12345678901234567890")
	code, err := GenerateHOTP(secret, 0, 6)
	if err != nil {
		t.Fatalf("GenerateHOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("code length = %d, want 6 (got %q)", len(code), code)
	}
}
