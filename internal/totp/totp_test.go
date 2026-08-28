package totp

import (
	"testing"
	"time"
)

// TestGenerateTOTP_RFC6238Vectors validates against the official RFC 6238
// Appendix B test vectors: 8-digit SHA-1 TOTP codes for the fixed 20-byte
// ASCII secret "12345678901234567890" at a 30-second step.
func TestGenerateTOTP_RFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")

	cases := []struct {
		unixTime int64
		want     string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range cases {
		got, err := GenerateTOTP(secret, time.Unix(tc.unixTime, 0).UTC(), 30, 8)
		if err != nil {
			t.Fatalf("GenerateTOTP(%d): %v", tc.unixTime, err)
		}
		if got != tc.want {
			t.Errorf("GenerateTOTP(%d) = %q, want %q", tc.unixTime, got, tc.want)
		}
	}
}

func TestNow_SixDigits(t *testing.T) {
	secret := []byte("12345678901234567890")
	code, err := Now(secret)
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("Now() returned %d digits, want 6", len(code))
	}
}

func TestValidate_ExactMatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0).UTC()
	code, err := GenerateTOTP(secret, now, 30, 8)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if !Validate(secret, code, now, 30, 8, 1) {
		t.Fatalf("Validate rejected a code generated for the same timestamp")
	}
}

func TestValidate_WithinWindowToleratesDrift(t *testing.T) {
	secret := []byte("12345678901234567890")
	base := time.Unix(1234567890, 0).UTC()
	// Code from one step (30s) earlier should still validate within window=1.
	earlier := base.Add(-30 * time.Second)
	code, err := GenerateTOTP(secret, earlier, 30, 8)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if !Validate(secret, code, base, 30, 8, 1) {
		t.Fatalf("Validate rejected a code from the adjacent time step within window")
	}
}

func TestValidate_OutsideWindowFails(t *testing.T) {
	secret := []byte("12345678901234567890")
	base := time.Unix(1234567890, 0).UTC()
	farAway := base.Add(-300 * time.Second) // 10 steps away
	code, err := GenerateTOTP(secret, farAway, 30, 8)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if Validate(secret, code, base, 30, 8, 1) {
		t.Fatalf("Validate accepted a code far outside the tolerance window")
	}
}

func TestValidate_WrongCodeFails(t *testing.T) {
	secret := []byte("12345678901234567890")
	if Validate(secret, "00000000", time.Unix(1234567890, 0).UTC(), 30, 8, 1) {
		t.Fatalf("Validate accepted an incorrect code")
	}
}

func TestRemainingSeconds_Bounds(t *testing.T) {
	t0 := time.Unix(0, 0).UTC() // exactly on a 30s boundary
	if got := RemainingSeconds(t0); got != 30 {
		t.Fatalf("RemainingSeconds at boundary = %d, want 30", got)
	}
	t15 := time.Unix(15, 0).UTC()
	if got := RemainingSeconds(t15); got != 15 {
		t.Fatalf("RemainingSeconds at +15s = %d, want 15", got)
	}
}
