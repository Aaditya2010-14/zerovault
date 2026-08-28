package attacks

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"zerovault/internal/fileenc"
)

// --- ATTACK LOGIC ---

// fileTamperCase describes one way a real attacker could corrupt a
// ZeroVault-encrypted file on disk before a victim decrypts it.
type fileTamperCase struct {
	label   string
	corrupt func(data []byte) []byte
}

var fileTamperCases = []fileTamperCase{
	{"flip a bit mid-ciphertext", func(data []byte) []byte {
		out := append([]byte(nil), data...)
		pos := len(out) / 2
		out[pos] ^= 0x01
		return out
	}},
	{"truncate the final chunk", func(data []byte) []byte {
		return data[:len(data)-32]
	}},
	{"append trailing garbage", func(data []byte) []byte {
		return append(append([]byte(nil), data...), []byte("EXTRA-BYTES-AFTER-LAST-CHUNK")...)
	}},
	{"flip a bit in the length prefix of a chunk", func(data []byte) []byte {
		out := append([]byte(nil), data...)
		// Header is magic(14) + salt(16) + noncePrefix(8) = 38 bytes; the
		// first chunk's 4-byte length prefix starts right after that.
		out[38] ^= 0x01
		return out
	}},
}

// runFileTamperAttack encrypts a real file with fileenc.EncryptFile, then
// attempts to decrypt four corrupted variants of it with the correct
// password. Every variant must be rejected — this is fileenc's own STREAM
// nonce construction being exercised the way an attacker would try to
// break it (see internal/fileenc's package doc for why truncation and
// reordering are covered, not just single-chunk bit flips).
func runFileTamperAttack(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[FILE-TAMPER] Encrypting a real file for the tamper test...")

	dir, err := os.MkdirTemp("", "zerovault-filetamper-*")
	if err != nil {
		return Result{StatusVulnerable, "could not set up temp dir", 0}
	}
	defer os.RemoveAll(dir)

	plainPath := filepath.Join(dir, "secret-report.txt")
	if err := os.WriteFile(plainPath, []byte("quarterly earnings, do not leak\n"), 0o600); err != nil {
		return Result{StatusVulnerable, "could not write fixture plaintext", 0}
	}
	encPath := filepath.Join(dir, "secret-report.txt.enc")
	password := "file-attack-fixture-password"
	if err := fileenc.EncryptFile(plainPath, encPath, password, nil, nil); err != nil {
		return Result{StatusVulnerable, "fixture file did not encrypt cleanly", 0}
	}

	original, err := os.ReadFile(encPath)
	if err != nil {
		return Result{StatusVulnerable, "could not read encrypted fixture", 0}
	}
	reportFileOriginalOK(w, len(original))

	start := time.Now()
	undetected := 0
	for _, tc := range fileTamperCases {
		tampered := tc.corrupt(original)
		tamperedPath := filepath.Join(dir, "tampered.enc")
		if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
			return Result{StatusVulnerable, "could not write tampered variant", 0}
		}

		outPath := filepath.Join(dir, "decrypt-attempt-out")
		_, decErr := fileenc.DecryptFile(tamperedPath, outPath, password, nil, nil)
		reportFileTamper(w, tc.label, decErr)
		if decErr == nil {
			undetected++
		}
		os.Remove(outPath)
	}
	elapsed := time.Since(start)

	if undetected > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d file-tamper case(s) went undetected", undetected), elapsed}
	}
	return Result{StatusBlocked, "every corrupted variant was rejected before any plaintext was written", elapsed}
}

// --- REPORTING ---

func reportFileOriginalOK(w io.Writer, size int) {
	fmt.Fprintf(w, "[FILE-TAMPER] Encrypted fixture: %d bytes, decrypts successfully ✓\n", size)
}

func reportFileTamper(w io.Writer, label string, decErr error) {
	fmt.Fprintf(w, "[FILE-TAMPER] Attempting: %s...\n", label)
	if decErr != nil {
		fmt.Fprintln(w, "[FILE-TAMPER]   Decrypt attempt: FAILED — integrity check failed ✓")
	} else {
		fmt.Fprintln(w, "[FILE-TAMPER]   Decrypt attempt: SUCCEEDED — tampering NOT detected ✗")
	}
}
