package attacks

import (
	"fmt"
	"io"
	"os"
	"time"

	vcrypto "zerovault/internal/crypto"
)

// commonPasswords is a small dictionary of the passwords real-world
// credential-stuffing lists lead with.
var commonPasswords = []string{
	"password", "123456", "admin", "letmein", "welcome", "monkey", "dragon",
	"master", "qwerty", "login", "abc123", "starwars", "trustno1", "iloveyou",
	"shadow", "123123", "654321", "superman", "batman", "access",
}

// --- ATTACK LOGIC ---

// dictAttempt is one password's real result: read the vault file's salt,
// run the actual PBKDF2 derivation ZeroVault uses (100,000 rounds of
// HMAC-SHA256), and attempt an actual AES-GCM open with the derived key.
func dictAttempt(vaultPath, guess string) (ok bool, elapsed time.Duration) {
	data, err := os.ReadFile(vaultPath)
	if err != nil || len(data) < vcrypto.SaltLen {
		return false, 0
	}
	salt, sealed := data[:vcrypto.SaltLen], data[vcrypto.SaltLen:]

	start := time.Now()
	key := vcrypto.DeriveKey([]byte(guess), salt)
	_, err = vcrypto.Decrypt(key, sealed)
	elapsed = time.Since(start)

	return err == nil, elapsed
}

// runBruteForce tries every password in commonPasswords against the real
// fixture vault on disk. The correct password is never in the list, so
// every attempt is expected to fail GCM authentication.
func runBruteForce(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "[BRUTEFORCE] Starting dictionary attack with %d common passwords...\n", len(commonPasswords))

	start := time.Now()
	var total time.Duration
	cracked := ""
	for _, guess := range commonPasswords {
		ok, elapsed := dictAttempt(h.vaultPath, guess)
		total += elapsed
		reportDictAttempt(w, guess, ok, elapsed)
		if ok {
			cracked = guess
			break
		}
	}
	overall := time.Since(start)

	avg := total / time.Duration(len(commonPasswords))
	reportDictSummary(w, len(commonPasswords), overall, avg)

	if cracked != "" {
		return Result{StatusVulnerable, fmt.Sprintf("vault opened with dictionary password %q", cracked), overall}
	}
	return Result{StatusBlocked, "all dictionary passwords rejected by GCM authentication", overall}
}

// --- REPORTING ---

func reportDictAttempt(w io.Writer, guess string, ok bool, elapsed time.Duration) {
	status := "FAILED"
	if ok {
		status = "SUCCEEDED"
	}
	fmt.Fprintf(w, "[BRUTEFORCE] Trying %-16q %s (%s)\n", guess, status, formatDuration(elapsed))
}

func reportDictSummary(w io.Writer, n int, total, avg time.Duration) {
	fmt.Fprintf(w, "[BRUTEFORCE] Tried %d passwords in %s\n", n, formatDuration(total))
	fmt.Fprintf(w, "[BRUTEFORCE] Average: %s per attempt (PBKDF2 100K rounds working as intended)\n", formatDuration(avg))

	perMillion := avg * 1_000_000
	perTenBillion := avg * 10_000_000_000
	fmt.Fprintf(w, "[BRUTEFORCE] Estimated time for 1M passwords: %.1f hours\n", perMillion.Hours())
	fmt.Fprintf(w, "[BRUTEFORCE] Estimated time for 10B passwords: %.1f years\n", perTenBillion.Hours()/24/365)
}
