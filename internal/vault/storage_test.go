package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestSave_CreatesMissingParentDirectory guards against a real bug found in
// the field: 'zerovault serve' on a freshly cloned repo (no prior 'zerovault
// init', so ~/.zerovault never existed) failed to create a vault from the
// web unlock form with a bare "failed to create vault" error, because
// writeFileAtomic's os.CreateTemp fails outright when its target directory
// doesn't exist yet. Save must create that directory itself rather than
// assuming a caller (like the CLI's dedicated init command) already did.
func TestSave_CreatesMissingParentDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "does-not-exist-yet", "vault.db")

	if err := Save(path, "master-pw", New()); err != nil {
		t.Fatalf("Save into a missing parent directory: %v", err)
	}

	if _, err := Load(path, "master-pw"); err != nil {
		t.Fatalf("Load after Save into a missing parent directory: %v", err)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	v := New()
	if _, err := v.Add("github", "octocat", "hunter2", "https://github.com", "notes"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := Save(path, "master-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path, "master-pw")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	entry, err := loaded.Get("github")
	if err != nil {
		t.Fatalf("Get after Load: %v", err)
	}
	if entry.Password != "hunter2" || entry.Username != "octocat" {
		t.Fatalf("round-tripped entry mismatch: %+v", entry)
	}
}

func TestSaveLoad_TOTPRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	v := New()
	if _, err := v.AddTOTP("github", testSecret, 6, 30); err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}

	if err := Save(path, "master-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path, "master-pw")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	entry, err := loaded.GetTOTP("github")
	if err != nil {
		t.Fatalf("GetTOTP after Load: %v", err)
	}
	if entry.Secret != testSecret {
		t.Fatalf("round-tripped TOTP secret mismatch: got %q", entry.Secret)
	}
}

func TestLoad_WrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	v := New()
	if err := Save(path, "correct-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := Load(path, "wrong-pw"); err == nil {
		t.Fatalf("Load succeeded with wrong password, want error")
	}
}

func TestLoad_MissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.vault"), "pw"); err == nil {
		t.Fatalf("Load succeeded on missing file, want error")
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	if Exists(path) {
		t.Fatalf("Exists returned true before file was created")
	}

	v := New()
	if err := Save(path, "pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !Exists(path) {
		t.Fatalf("Exists returned false after file was created")
	}
}

func TestRekey_ChangesEncryptionAndPreservesEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	v := New()
	if _, err := v.Add("github", "octocat", "hunter2", "https://github.com", "notes"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := v.AddTOTP("github", testSecret, 6, 30); err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	if err := Save(path, "old-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rekeyed, err := Rekey(path, "old-pw", "new-pw")
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("expected vault file bytes to change after rekey (new salt/key)")
	}

	if _, err := Load(path, "old-pw"); err == nil {
		t.Fatal("expected old password to no longer work after rekey")
	}
	if _, err := Load(path, "new-pw"); err != nil {
		t.Fatalf("expected new password to work after rekey: %v", err)
	}

	entry, err := rekeyed.Get("github")
	if err != nil {
		t.Fatalf("entry lost during rekey: %v", err)
	}
	if entry.Password != "hunter2" {
		t.Fatalf("entry password mismatch after rekey: got %q", entry.Password)
	}
	totpEntry, err := rekeyed.GetTOTP("github")
	if err != nil {
		t.Fatalf("TOTP entry lost during rekey: %v", err)
	}
	if totpEntry.Secret != testSecret {
		t.Fatalf("TOTP secret mismatch after rekey: got %q", totpEntry.Secret)
	}
}

func TestRekey_WrongCurrentPasswordFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	if err := Save(path, "correct-pw", New()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Rekey(path, "wrong-pw", "new-pw"); err == nil {
		t.Fatal("expected Rekey to fail with the wrong current password")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("vault file must be untouched when rekey fails to unlock with the current password")
	}
}

func TestSave_SaltDiffersEachTime(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "a.vault")
	path2 := filepath.Join(dir, "b.vault")

	v := New()
	if err := Save(path1, "same-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := Save(path2, "same-pw", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Both must still load correctly with the same password despite
	// different on-disk bytes (different random salt/nonce each save).
	if _, err := Load(path1, "same-pw"); err != nil {
		t.Fatalf("Load path1: %v", err)
	}
	if _, err := Load(path2, "same-pw"); err != nil {
		t.Fatalf("Load path2: %v", err)
	}
}

// TestSave_ConcurrentSavesToSamePathDoNotCorrupt guards against the temp-file
// collision bug fixed in writeFileAtomic: two goroutines racing to Save the
// same vault path used to collide on a single fixed "path.tmp" name (one
// writer's os.Rename could fail, or on some platforms clobber the other
// writer's in-progress temp file). Each Save now gets a unique temp file via
// os.CreateTemp, so concurrent saves should never error and the file left
// behind afterward must always be a complete, loadable vault (last-write-wins
// is fine; corruption is not).
func TestSave_ConcurrentSavesToSamePathDoNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.vault")

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := New()
			if _, err := v.Add("entry", "user", "pw", "", ""); err != nil {
				errs[i] = err
				return
			}
			errs[i] = Save(path, "same-pw", v)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Save %d failed: %v", i, err)
		}
	}

	// The file left behind must be a fully-formed, loadable vault — not a
	// half-written or corrupted one from a botched rename.
	if _, err := Load(path, "same-pw"); err != nil {
		t.Fatalf("Load after concurrent saves: %v", err)
	}

	// No stray *.tmp files should be left behind in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file after concurrent saves: %s", e.Name())
		}
	}
}
