package gitscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runGit shells out to the real git binary purely to construct a test
// fixture repository — this is test infrastructure, not something
// zerovault itself does at runtime (the whole point of this package is
// that ScanRepo never shells out to git). If git isn't installed on the
// machine running `go test`, these tests are skipped rather than failed.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=dev@example.com",
		"GIT_AUTHOR_DATE=2026-08-01T12:00:00",
		"GIT_COMMITTER_NAME=Test Author",
		"GIT_COMMITTER_EMAIL=dev@example.com",
		"GIT_COMMITTER_DATE=2026-08-01T12:00:00",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available — skipping gitscan fixture-based test")
	}
}

func TestScanRepoFindsSecretInHistory(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()

	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "config", "commit.gpgsign", "false")

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "initial commit")

	// Commit a real-looking AWS key, then delete it in a later commit —
	// this is the "deleted but still in history" scenario.
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte("AWS_KEY = \"AKIAABCDEFGHIJKLMNOP\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "add config with secret")

	if err := os.Remove(filepath.Join(dir, "config.py")); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "remove config")

	report, err := ScanRepo(dir, 50, 3.5)
	if err != nil {
		t.Fatalf("ScanRepo: %v", err)
	}
	if report.CommitsScanned != 3 {
		t.Fatalf("expected 3 commits scanned, got %d", report.CommitsScanned)
	}

	var found *Finding
	for i := range report.Findings {
		if report.Findings[i].Path == "config.py" {
			found = &report.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected to find the AWS key in config.py's history, findings: %+v", report.Findings)
	}
	if found.Pattern != "AWS Access Key ID" {
		t.Errorf("expected pattern 'AWS Access Key ID', got %q", found.Pattern)
	}
	if !found.DeletedLater {
		t.Error("expected DeletedLater to be true — config.py was removed in the final commit")
	}
	if found.Author != "dev@example.com" {
		t.Errorf("expected author dev@example.com, got %q", found.Author)
	}
}

func TestScanRepoNotAGitRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := ScanRepo(dir, 50, 3.5)
	if err != ErrNotAGitRepo {
		t.Fatalf("expected ErrNotAGitRepo, got %v", err)
	}
}

func TestScanRepoDepthLimiting(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "config", "commit.gpgsign", "false")

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(contentVersion(i)), 0o644); err != nil {
			t.Fatal(err)
		}
		runGit(t, dir, "add", ".")
		runGit(t, dir, "commit", "-q", "-m", "commit")
	}

	report, err := ScanRepo(dir, 2, 3.5)
	if err != nil {
		t.Fatalf("ScanRepo: %v", err)
	}
	if report.CommitsScanned != 2 {
		t.Fatalf("expected depth limit of 2 commits, got %d", report.CommitsScanned)
	}
	if !report.Truncated {
		t.Error("expected Truncated to be true when history exceeds the depth limit")
	}
}

func TestScanRepoBinaryBlobSkipped(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "config", "commit.gpgsign", "false")

	binary := []byte{0x00, 0x01, 0x02, 'A', 'K', 'I', 'A', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 0x00}
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), binary, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "add binary")

	report, err := ScanRepo(dir, 50, 3.5)
	if err != nil {
		t.Fatalf("ScanRepo: %v", err)
	}
	for _, f := range report.Findings {
		if f.Path == "data.bin" {
			t.Fatalf("expected binary file to be skipped, but got a finding: %+v", f)
		}
	}
}

func contentVersion(i int) string {
	return "content version " + string(rune('0'+i)) + "\n"
}
