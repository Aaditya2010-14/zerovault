package crypto

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// TestPBKDF2_RFC6070 validates the PBKDF2 algorithm itself (the F/T-block
// construction) against the official RFC 6070 test vectors, which are
// defined for PBKDF2-HMAC-SHA1. ZeroVault uses PBKDF2-HMAC-SHA256 for actual
// key derivation (see DeriveKey), but the RFC 6070 vectors are the standard
// way to prove the PBKDF2 implementation is correct before trusting it with
// any hash function.
func TestPBKDF2_RFC6070(t *testing.T) {
	cases := []struct {
		name       string
		password   string
		salt       string
		iterations int
		keyLen     int
		want       string
	}{
		{
			name:       "vector1",
			password:   "password",
			salt:       "salt",
			iterations: 1,
			keyLen:     20,
			want:       "0c60c80f961f0e71f3a9b524af6012062fe037a6",
		},
		{
			name:       "vector2",
			password:   "password",
			salt:       "salt",
			iterations: 2,
			keyLen:     20,
			want:       "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
		},
		{
			name:       "vector3",
			password:   "password",
			salt:       "salt",
			iterations: 4096,
			keyLen:     20,
			want:       "4b007901b765489abead49d926f721d065a429c1",
		},
		{
			name:       "vector5_longer_password_and_salt",
			password:   "passwordPASSWORDpassword",
			salt:       "saltSALTsaltSALTsaltSALTsaltSALTsalt",
			iterations: 4096,
			keyLen:     25,
			want:       "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
		},
		{
			name:       "vector6_embedded_null",
			password:   "pass\x00word",
			salt:       "sa\x00lt",
			iterations: 4096,
			keyLen:     16,
			want:       "56fa6aa75548099dcc37d7f03425e0c3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("bad test vector hex: %v", err)
			}
			got := PBKDF2([]byte(tc.password), []byte(tc.salt), tc.iterations, tc.keyLen, sha1.New)
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("PBKDF2 mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestPBKDF2_RFC6070_Vector4 is the RFC 6070 vector with c=16,777,216
// iterations. It is correct but slow (tens of seconds), so it is skipped
// under `go test -short`.
func TestPBKDF2_RFC6070_Vector4(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow 16,777,216-iteration RFC 6070 vector in -short mode")
	}
	want, err := hex.DecodeString("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
	if err != nil {
		t.Fatalf("bad test vector hex: %v", err)
	}
	got := PBKDF2([]byte("password"), []byte("salt"), 16777216, 20, sha1.New)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("PBKDF2 mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestDeriveKey_Length(t *testing.T) {
	key := DeriveKey([]byte("hunter2"), []byte("0123456789abcdef"))
	if len(key) != PBKDF2KeyLen {
		t.Fatalf("DeriveKey returned %d bytes, want %d", len(key), PBKDF2KeyLen)
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := DeriveKey([]byte("hunter2"), salt)
	k2 := DeriveKey([]byte("hunter2"), salt)
	if hex.EncodeToString(k1) != hex.EncodeToString(k2) {
		t.Fatalf("DeriveKey not deterministic for same password+salt")
	}
}

func TestDeriveKey_DifferentSaltsDifferentKeys(t *testing.T) {
	k1 := DeriveKey([]byte("hunter2"), []byte("0123456789abcdef"))
	k2 := DeriveKey([]byte("hunter2"), []byte("fedcba9876543210"))
	if hex.EncodeToString(k1) == hex.EncodeToString(k2) {
		t.Fatalf("DeriveKey produced same key for different salts")
	}
}
