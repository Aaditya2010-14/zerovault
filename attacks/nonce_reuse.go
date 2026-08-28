package attacks

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	vcrypto "zerovault/internal/crypto"
	"zerovault/internal/vault"
)

// --- ATTACK LOGIC ---

// saveAndExtractNonce performs a real vault.Save (the same call path
// `zerovault add` and the dashboard use) and pulls the GCM nonce out of
// the resulting file: salt(16) || nonce(12) || ciphertext || tag.
func saveAndExtractNonce(path, password string, v *vault.Vault) ([]byte, error) {
	if err := vault.Save(path, password, v); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	start := vcrypto.SaltLen
	end := start + vcrypto.NonceLen
	if len(data) < end {
		return nil, fmt.Errorf("saved vault too short to contain a nonce")
	}
	nonce := make([]byte, vcrypto.NonceLen)
	copy(nonce, data[start:end])
	return nonce, nil
}

// runNonceReuse saves the fixture vault 100 times in a row — each save is
// a real encrypt-and-write, drawing a fresh nonce from crypto/rand — and
// checks whether any two of the resulting nonces collide. AES-GCM nonce
// reuse is catastrophic (it breaks both confidentiality and integrity),
// so this is the single highest-value crypto attack in the suite.
func runNonceReuse(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[NONCE] Checking nonce uniqueness across 100 vault saves...")

	// A dedicated path, not h.vaultPath: this attack repeatedly overwrites
	// the file it saves to, so it must not disturb the shared fixture
	// vault that later web attacks (XSS, CSRF, TOTP) still need intact.
	probePath := filepath.Join(h.dir, "nonce-probe.vault")

	v := vault.New()
	if _, err := v.Add("probe", "", "probe-password", "", ""); err != nil {
		return Result{StatusVulnerable, "failed to build probe vault", 0}
	}

	const n = 100
	seen := make(map[string]int, n)
	var collisions []string

	start := time.Now()
	for i := 1; i <= n; i++ {
		nonce, err := saveAndExtractNonce(probePath, h.masterPw, v)
		if err != nil {
			return Result{StatusVulnerable, fmt.Sprintf("save %d failed: %v", i, err), time.Since(start)}
		}
		hexNonce := hex.EncodeToString(nonce)
		if prior, dup := seen[hexNonce]; dup {
			collisions = append(collisions, fmt.Sprintf("save %d repeats save %d's nonce", i, prior))
		}
		seen[hexNonce] = i

		if i <= 2 || i == n {
			reportNonceSave(w, i, hexNonce)
		} else if i == 3 {
			fmt.Fprintln(w, "[NONCE] ...")
		}
	}
	elapsed := time.Since(start)

	if len(collisions) > 0 {
		reportCollisions(w, collisions)
		return Result{StatusVulnerable, fmt.Sprintf("%d nonce collision(s) detected", len(collisions)), elapsed}
	}
	reportAllUnique(w, n)
	return Result{StatusSecure, "no nonce reuse detected (crypto/rand working correctly)", elapsed}
}

// --- REPORTING ---

func reportNonceSave(w io.Writer, i int, hexNonce string) {
	fmt.Fprintf(w, "[NONCE] Save %-3d nonce=%s ✓ unique\n", i, hexNonce)
}

func reportAllUnique(w io.Writer, n int) {
	fmt.Fprintf(w, "[NONCE] All %d nonces are unique\n", n)
}

func reportCollisions(w io.Writer, collisions []string) {
	for _, c := range collisions {
		fmt.Fprintf(w, "[NONCE] ✗ COLLISION: %s\n", c)
	}
}
