package attacks

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"time"

	vcrypto "zerovault/internal/crypto"
)

// --- ATTACK LOGIC ---

// truncationStrategy is one way of mangling the vault file's byte layout.
type truncationStrategy struct {
	label string
	apply func(original []byte) []byte
}

var truncationStrategies = []truncationStrategy{
	{
		"Removing auth tag (last 16 bytes)",
		func(b []byte) []byte { return b[:len(b)-16] },
	},
	{
		"Truncating 100 bytes off the end",
		func(b []byte) []byte { return b[:len(b)-100] },
	},
	{
		"Keeping only salt+nonce (28 bytes)",
		func(b []byte) []byte { return b[:vcrypto.SaltLen+vcrypto.NonceLen] },
	},
	{
		"Appending 100 random bytes",
		func(b []byte) []byte {
			extra := make([]byte, 100)
			rand.Read(extra)
			out := make([]byte, 0, len(b)+len(extra))
			out = append(out, b...)
			out = append(out, extra...)
			return out
		},
	},
}

// runTruncationTamper applies each strategy to an in-memory copy of the
// real vault bytes and attempts a real decrypt with the correct master
// password. Every strategy either strips authenticated data (caught by
// the GCM tag) or removes so much of the file that decryption cannot
// even start (caught by the length check in Decrypt).
func runTruncationTamper(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TRUNCATE] Starting vault truncation/injection attack...")

	original, err := os.ReadFile(h.vaultPath)
	if err != nil {
		return Result{StatusVulnerable, "could not read fixture vault", 0}
	}

	start := time.Now()
	undetected := 0
	for _, strat := range truncationStrategies {
		mangled := strat.apply(original)
		err := attemptDecrypt(mangled, h.masterPw)
		reportTruncateStrategy(w, strat.label, err)
		if err == nil {
			undetected++
		}
	}
	elapsed := time.Since(start)

	if undetected > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d truncation/injection attempt(s) went undetected", undetected), elapsed}
	}
	return Result{StatusBlocked, "all truncation/injection attempts rejected", elapsed}
}

// --- REPORTING ---

func reportTruncateStrategy(w io.Writer, label string, decryptErr error) {
	fmt.Fprintf(w, "[TRUNCATE] %s...\n", label)
	if decryptErr != nil {
		fmt.Fprintf(w, "[TRUNCATE]   Decrypt: FAILED — %v ✓\n", decryptErr)
	} else {
		fmt.Fprintln(w, "[TRUNCATE]   Decrypt: SUCCEEDED — mangled vault accepted ✗")
	}
}
