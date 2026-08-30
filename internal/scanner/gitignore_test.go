package scanner

import (
	"testing"
)

func TestScanDir_SkipsFileListedInGitignore(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".gitignore", "secrets.env\n")
	writeTestFile(t, dir, "secrets.env", `AWS_KEY=AKIAIOSFODNN7EXAMPLE`)

	findings, err := ScanDir(dir, Options{})
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if hasPattern(findings, "AWS Access Key ID") {
		t.Fatalf("expected secrets.env to be skipped as gitignored, got findings: %+v", findings)
	}
}

func TestScanDir_FlagsFileNotListedInGitignore(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".gitignore", "secrets.env\n")
	writeTestFile(t, dir, "config.env", `AWS_KEY=AKIAIOSFODNN7EXAMPLE`)

	findings, err := ScanDir(dir, Options{})
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if !hasPattern(findings, "AWS Access Key ID") {
		t.Fatalf("expected config.env (not gitignored) to be flagged, got: %+v", findings)
	}
}
