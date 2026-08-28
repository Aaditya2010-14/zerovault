package totp

import (
	"crypto/subtle"
	"fmt"
	"time"
)

const (
	// DefaultPeriod is the standard TOTP time step in seconds (RFC 6238).
	DefaultPeriod = 30
	// DefaultDigits is the standard TOTP code length used by Google
	// Authenticator and most compatible apps.
	DefaultDigits = 6
)

// GenerateTOTP produces the current RFC 6238 TOTP code for key at time t,
// using the given step period (seconds) and digit count.
func GenerateTOTP(key []byte, t time.Time, period, digits int) (string, error) {
	if period <= 0 {
		return "", fmt.Errorf("totp: period must be positive, got %d", period)
	}
	counter := uint64(t.Unix() / int64(period))
	return GenerateHOTP(key, counter, digits)
}

// Now generates the current TOTP code for key using DefaultPeriod and
// DefaultDigits — the common case for Google Authenticator compatibility.
func Now(key []byte) (string, error) {
	return GenerateTOTP(key, time.Now(), DefaultPeriod, DefaultDigits)
}

// RemainingSeconds returns how many seconds remain until the current TOTP
// code (at DefaultPeriod) expires and a new one is generated.
func RemainingSeconds(t time.Time) int {
	period := int64(DefaultPeriod)
	elapsed := t.Unix() % period
	return int(period - elapsed)
}

// Validate reports whether code matches the TOTP for key at time t, within
// +/- window time steps to tolerate clock drift between client and server
// (a window of 1 allows the previous and next 30s step to also match).
func Validate(key []byte, code string, t time.Time, period, digits, window int) bool {
	if period <= 0 {
		return false
	}
	counter := t.Unix() / int64(period)
	for i := -window; i <= window; i++ {
		want, err := GenerateHOTP(key, uint64(counter+int64(i)), digits)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
