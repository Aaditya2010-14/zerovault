package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func hasPattern(findings []Finding, name string) bool {
	for _, f := range findings {
		if f.Pattern == name {
			return true
		}
	}
	return false
}

func TestScanFile_DetectsAWSAccessKey(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "config.go", `awsKey := "AKIAIOSFODNN7EXAMPLE"`)

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasPattern(findings, "AWS Access Key ID") {
		t.Fatalf("expected AWS Access Key ID finding, got: %+v", findings)
	}
}

func TestScanFile_DetectsGitHubToken(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, ".env", "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz")

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasPattern(findings, "GitHub Personal Access Token") {
		t.Fatalf("expected GitHub PAT finding, got: %+v", findings)
	}
}

func TestScanFile_DetectsPrivateKeyBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----")

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasPattern(findings, "PGP/RSA/EC Private Key Block") {
		t.Fatalf("expected private key finding, got: %+v", findings)
	}
}

func TestScanFile_DetectsHighEntropyGenericSecret(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "settings.py", `secret_key = "xK9mQ2pL7vR4jN8wZ3fB6hT1cY5aE0dU"`)

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a high-entropy warning finding, got: %+v", findings)
	}
}

func TestScanFile_NoFalsePositiveOnNormalCode(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "main.go", `
package main

import "fmt"

func main() {
	name := "world"
	fmt.Printf("hello, %s\n", name)
}
`)

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on ordinary code, got: %+v", findings)
	}
}

func TestScanFile_RedactsMatchedSecret(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "config.go", `awsKey := "AKIAIOSFODNN7EXAMPLE"`)

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	for _, f := range findings {
		if f.Match == "AKIAIOSFODNN7EXAMPLE" {
			t.Fatalf("finding leaked the full unredacted secret: %q", f.Match)
		}
	}
}

func TestScanFile_SkipsBinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	// Embed a NUL byte plus an AWS-key-shaped string that should NOT be
	// reported since the file is binary.
	content := append([]byte("AKIAIOSFODNN7EXAMPLE"), 0x00, 0x01, 0x02)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanFile(path, MinEntropy)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected binary file to be skipped, got: %+v", findings)
	}
}

func TestScanDir_WalksSubdirectoriesAndSkipsVendor(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "src/app.go", `key := "AKIAIOSFODNN7EXAMPLE"`)
	writeTestFile(t, dir, "vendor/lib/leaked.go", `key := "AKIAIOSFODNN7EXAMPLE"`)
	writeTestFile(t, dir, ".git/config", `key := "AKIAIOSFODNN7EXAMPLE"`)

	findings, err := ScanDir(dir, Options{})
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (vendor/.git skipped), got %d: %+v", len(findings), findings)
	}
	if findings[0].File != filepath.Join(dir, "src/app.go") {
		t.Fatalf("finding came from unexpected file: %s", findings[0].File)
	}
}

func TestScanDir_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "big.txt", `key := "AKIAIOSFODNN7EXAMPLE"`)

	findings, err := ScanDir(dir, Options{MaxFileSize: 1}) // 1 byte max — everything skipped
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	_ = path
	if len(findings) != 0 {
		t.Fatalf("expected no findings when MaxFileSize excludes all files, got: %+v", findings)
	}
}
