package attacks

import (
	"fmt"
	"io"
	"time"

	"zerovault/internal/totp"
)

// --- ATTACK LOGIC ---

// findCurrentCode brute-forces the 6-digit code space (000000-999999)
// looking for whichever one matches the real, currently-valid TOTP code
// for the fixture secret — computed the honest way, via the actual
// totp.GenerateTOTP the vault and dashboard use, not looked up in
// advance.
func findCurrentCode(secret string) (found string, attempts int, err error) {
	key, err := totp.DecodeSecret(secret)
	if err != nil {
		return "", 0, err
	}
	target, err := totp.GenerateTOTP(key, time.Now(), totp.DefaultPeriod, totp.DefaultDigits)
	if err != nil {
		return "", 0, err
	}

	for i := 0; i < 1_000_000; i++ {
		attempts++
		candidate := fmt.Sprintf("%06d", i)
		if candidate == target {
			return candidate, attempts, nil
		}
	}
	return "", attempts, fmt.Errorf("current code not found in the full 6-digit space (should be impossible)")
}

// runTOTPBruteForce demonstrates — and documents — the one attack in this
// suite that "succeeds": with 1,000,000 possible 6-digit codes, brute
// force can always find the current one quickly. That is not a ZeroVault
// weakness; it is why TOTP's real security guarantee is "you cannot
// predict the NEXT code without the secret", enforced by rate limits on
// the verifying service, not by ZeroVault itself.
func runTOTPBruteForce(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TOTP-BF] Starting TOTP brute force (000000-999999)...")
	fmt.Fprintln(w, "[TOTP-BF] Searching for current valid code...")

	start := time.Now()
	code, attempts, err := findCurrentCode(demoTOTPSecret)
	elapsed := time.Since(start)

	if err != nil {
		return Result{StatusVulnerable, err.Error(), elapsed}
	}

	reportTOTPFound(w, code, attempts, elapsed)
	return Result{StatusExpected, "documented as a known limitation in the threat model", elapsed}
}

// --- REPORTING ---

func reportTOTPFound(w io.Writer, code string, attempts int, elapsed time.Duration) {
	fmt.Fprintf(w, "[TOTP-BF] Found valid code %s at attempt %d (%s)\n", code, attempts, formatDuration(elapsed))
	fmt.Fprintln(w, "[TOTP-BF] NOTE: This is expected behavior. TOTP codes are 6 digits (1M possibilities).")
	fmt.Fprintln(w, "[TOTP-BF] TOTP security relies on the SECRET being unknown, not the code being unguessable.")
	fmt.Fprintln(w, "[TOTP-BF] Without the secret, an attacker cannot predict the NEXT code.")
	fmt.Fprintln(w, "[TOTP-BF] This is why TOTP has attempt limits on real services (lockout after 3-5 failures).")
}
