package fileenc

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func hashFile(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return sha256.Sum256(data)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	content := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 1000)
	if err := os.WriteFile(in, content, 0o600); err != nil {
		t.Fatal(err)
	}

	enc := filepath.Join(dir, "secret.txt.enc")
	if err := EncryptFile(in, enc, "correct horse battery staple", nil, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out := filepath.Join(dir, "recovered.txt")
	usedPath, err := DecryptFile(enc, out, "correct horse battery staple", nil, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if usedPath != out {
		t.Fatalf("expected used path %q, got %q", out, usedPath)
	}

	wantHash := hashFile(t, in)
	gotHash := hashFile(t, out)
	if wantHash != gotHash {
		t.Fatalf("round-trip content mismatch: SHA-256 differs")
	}
}

func TestDecryptWrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(in, []byte("top secret payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "data.bin.enc")
	if err := EncryptFile(in, enc, "rightpassword", nil, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out := filepath.Join(dir, "out.bin")
	if _, err := DecryptFile(enc, out, "wrongpassword", nil, nil); err == nil {
		t.Fatal("expected decryption with wrong password to fail")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("output file should not exist after a failed decrypt")
	}
}

func TestTamperedFileDetected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(in, bytes.Repeat([]byte("A"), 200*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "data.bin.enc")
	if err := EncryptFile(in, enc, "pw", nil, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	data, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte well past the header, inside a ciphertext chunk.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-100] ^= 0xFF
	tamperedPath := filepath.Join(dir, "tampered.enc")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "out.bin")
	if _, err := DecryptFile(tamperedPath, out, "pw", nil, nil); err == nil {
		t.Fatal("expected tampered file to be rejected")
	}
}

func TestTruncatedFileDetected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(in, bytes.Repeat([]byte("B"), 300*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "data.bin.enc")
	if err := EncryptFile(in, enc, "pw", nil, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	data, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	truncated := data[:len(data)-500] // drop the tail, including the final-chunk marker
	truncatedPath := filepath.Join(dir, "truncated.enc")
	if err := os.WriteFile(truncatedPath, truncated, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "out.bin")
	if _, err := DecryptFile(truncatedPath, out, "pw", nil, nil); err == nil {
		t.Fatal("expected truncated file to be rejected")
	}
}

func TestEmptyFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(in, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "empty.txt.enc")
	if err := EncryptFile(in, enc, "pw", nil, nil); err != nil {
		t.Fatalf("encrypt empty file: %v", err)
	}
	out := filepath.Join(dir, "out.txt")
	if _, err := DecryptFile(enc, out, "pw", nil, nil); err != nil {
		t.Fatalf("decrypt empty file: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(data))
	}
}

func TestLargeFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "large.bin")
	// 10MB, exceeds several chunk boundaries.
	content := make([]byte, 10*1024*1024)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(in, content, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "large.bin.enc")
	var lastPct int64
	if err := EncryptFile(in, enc, "pw", nil, func(written, total int64) {
		lastPct = written * 100 / total
	}); err != nil {
		t.Fatalf("encrypt large file: %v", err)
	}
	if lastPct != 100 {
		t.Fatalf("expected progress to reach 100%%, got %d%%", lastPct)
	}

	out := filepath.Join(dir, "large_out.bin")
	if _, err := DecryptFile(enc, out, "pw", nil, nil); err != nil {
		t.Fatalf("decrypt large file: %v", err)
	}
	if hashFile(t, in) != hashFile(t, out) {
		t.Fatal("large file round-trip content mismatch")
	}
}

func TestWrongMagicHeaderRejected(t *testing.T) {
	dir := t.TempDir()
	notEnc := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(notEnc, []byte("just a normal file"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	_, err := DecryptFile(notEnc, out, "pw", nil, nil)
	if err != ErrNotZeroVaultFile {
		t.Fatalf("expected ErrNotZeroVaultFile, got %v", err)
	}
}

func TestFileNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := EncryptFile(filepath.Join(dir, "nope.txt"), filepath.Join(dir, "nope.enc"), "pw", nil, nil); err == nil {
		t.Fatal("expected error for missing input file")
	}
}

func TestOverwriteDeclined(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	os.WriteFile(in, []byte("hello"), 0o600)
	enc := filepath.Join(dir, "a.txt.enc")
	os.WriteFile(enc, []byte("existing"), 0o600)

	err := EncryptFile(in, enc, "pw", func(string) (bool, error) { return false, nil }, nil)
	if err != ErrOverwriteDeclined {
		t.Fatalf("expected ErrOverwriteDeclined, got %v", err)
	}
}

func TestIsZeroVaultFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	os.WriteFile(in, []byte("hello"), 0o600)
	enc := filepath.Join(dir, "a.txt.enc")
	if err := EncryptFile(in, enc, "pw", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !IsZeroVaultFile(enc) {
		t.Fatal("expected encrypted file to be recognized")
	}
	if IsZeroVaultFile(in) {
		t.Fatal("expected plaintext file to not be recognized")
	}
}
