package attacks

import (
	"fmt"
	"io"
	"os"
	"time"

	vcrypto "zerovault/internal/crypto"
)

// --- ATTACK LOGIC ---

// bitFlipPositions describes where, relative to the file length, each
// flip lands — chosen to hit the salt boundary, the GCM nonce, early/mid/
// late ciphertext, and the trailing auth tag.
type bitFlipPositions struct {
	label string
	frac  float64 // fraction of file length (0.0-1.0)
}

var flipTargets = []bitFlipPositions{
	{"nonce region", 0.08},
	{"early ciphertext", 0.15},
	{"mid ciphertext", 0.50},
	{"late ciphertext", 0.85},
	{"auth tag region", 0.995},
}

// attemptDecrypt tries the real Load-equivalent decrypt path against
// possibly-corrupted vault bytes using the correct master password.
func attemptDecrypt(data []byte, password string) error {
	if len(data) < vcrypto.SaltLen {
		return fmt.Errorf("vault too short")
	}
	salt, sealed := data[:vcrypto.SaltLen], data[vcrypto.SaltLen:]
	key := vcrypto.DeriveKey([]byte(password), salt)
	_, err := vcrypto.Decrypt(key, sealed)
	return err
}

// flipBitAt returns a copy of data with a single bit flipped at the given
// byte offset.
func flipBitAt(data []byte, pos int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	out[pos] ^= 0x01
	return out
}

// runBitFlipTamper reads the real vault file, confirms it decrypts
// cleanly, then flips one bit at five different byte offsets and attempts
// a real decrypt after each flip. GCM's authentication tag covers the
// whole ciphertext, so every flip must be caught.
func runBitFlipTamper(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TAMPER] Starting vault tampering attack...")

	original, err := os.ReadFile(h.vaultPath)
	if err != nil {
		return Result{StatusVulnerable, "could not read fixture vault", 0}
	}
	if err := attemptDecrypt(original, h.masterPw); err != nil {
		return Result{StatusVulnerable, "fixture vault does not decrypt cleanly to begin with", 0}
	}
	reportOriginalOK(w, len(original))

	start := time.Now()
	undetected := 0
	for _, target := range flipTargets {
		pos := int(float64(len(original)-1) * target.frac)
		tampered := flipBitAt(original, pos)

		err := attemptDecrypt(tampered, h.masterPw)
		reportFlip(w, pos, target.label, err)
		if err == nil {
			undetected++
		}
	}
	elapsed := time.Since(start)

	if undetected > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d bit-flip(s) went undetected", undetected), elapsed}
	}
	return Result{StatusBlocked, "GCM authentication tag caught every tampered byte", elapsed}
}

// --- REPORTING ---

func reportOriginalOK(w io.Writer, size int) {
	fmt.Fprintf(w, "[TAMPER] Original vault: %d bytes, decrypts successfully ✓\n", size)
}

func reportFlip(w io.Writer, pos int, label string, decryptErr error) {
	fmt.Fprintf(w, "[TAMPER] Flipping bit at position %d (%s)...\n", pos, label)
	if decryptErr != nil {
		fmt.Fprintln(w, "[TAMPER]   Decrypt attempt: FAILED — integrity check failed ✓")
	} else {
		fmt.Fprintln(w, "[TAMPER]   Decrypt attempt: SUCCEEDED — tampering NOT detected ✗")
	}
}
