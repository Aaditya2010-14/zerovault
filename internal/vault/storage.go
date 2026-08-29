package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	json "encoding/json/v2"

	vcrypto "zerovault/internal/crypto"
)

// Vault file on disk layout: salt(16) || nonce(12) || AES-256-GCM ciphertext
// (nonce is produced by vcrypto.Encrypt, which already prepends it to the
// sealed ciphertext, so the on-disk format is simply salt || sealed).
const filePerm = 0o600

// Save serializes the vault to JSON, encrypts it under a key derived from
// password with a fresh random salt, and writes it atomically to path.
func Save(path, password string, v *Vault) error {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("vault: failed to serialize vault: %w", err)
	}

	salt, err := vcrypto.RandomSalt()
	if err != nil {
		return fmt.Errorf("vault: failed to generate salt: %w", err)
	}

	key := vcrypto.DeriveKey([]byte(password), salt)
	sealed, err := vcrypto.Encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("vault: failed to encrypt vault: %w", err)
	}

	out := make([]byte, 0, len(salt)+len(sealed))
	out = append(out, salt...)
	out = append(out, sealed...)

	return writeFileAtomic(path, out)
}

// Load reads an encrypted vault file from path, derives the key from
// password using the salt stored in the file, and decrypts + deserializes
// it. It returns an error if the file is missing, malformed, or the
// password is wrong (GCM auth failure).
func Load(path, password string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to read vault file: %w", err)
	}

	if len(data) < vcrypto.SaltLen {
		return nil, fmt.Errorf("vault: vault file is corrupted (too short)")
	}
	salt, sealed := data[:vcrypto.SaltLen], data[vcrypto.SaltLen:]

	key := vcrypto.DeriveKey([]byte(password), salt)
	plaintext, err := vcrypto.Decrypt(key, sealed)
	if err != nil {
		return nil, fmt.Errorf("vault: incorrect master password or corrupted vault")
	}

	v := &Vault{}
	if err := json.Unmarshal(plaintext, v); err != nil {
		return nil, fmt.Errorf("vault: failed to parse decrypted vault: %w", err)
	}
	return v, nil
}

// Rekey re-encrypts the vault at path under a new master password: it
// loads with oldPassword, saves with newPassword (which draws a fresh
// random salt via Save, exactly as if the vault were being created for
// the first time), and — as a final check that the new password actually
// works — immediately loads it back with newPassword. Save's atomic
// write (temp file + rename) means a crash mid-rekey leaves either the
// untouched old vault or the fully-written new one, never a corrupted
// partial file.
func Rekey(path, oldPassword, newPassword string) (*Vault, error) {
	v, err := Load(path, oldPassword)
	if err != nil {
		return nil, fmt.Errorf("vault: rekey failed to unlock with current password: %w", err)
	}

	if err := Save(path, newPassword, v); err != nil {
		return nil, fmt.Errorf("vault: rekey failed to save under new password: %w", err)
	}

	verified, err := Load(path, newPassword)
	if err != nil {
		return nil, fmt.Errorf("vault: rekey saved but failed to verify with the new password: %w", err)
	}
	return verified, nil
}

// Exists reports whether a vault file already exists at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeFileAtomic writes data to a uniquely-named temp file in the same
// directory as path and renames it into place, avoiding a truncated or
// corrupted vault file if the process is interrupted mid-write. Each call
// gets its own temp file (via os.CreateTemp, not a fixed "path.tmp" name)
// specifically so that two saves racing against the same vault path — e.g.
// two browser tabs open on the same session — never collide trying to
// write or rename the same temp file out from under each other; the last
// rename to complete simply wins, which is the same last-write-wins
// behavior any concurrent save to one file would have anyway.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	// The vault's parent directory (~/.zerovault by default) may not exist
	// yet — e.g. a freshly cloned repo where 'zerovault serve' is run
	// directly and a vault is created from the web unlock form, which
	// never had the CLI's own 'init' command run first to create it.
	// os.CreateTemp fails outright if dir is missing, so ensure it exists
	// before every write, not just on the CLI's dedicated init path.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vault: failed to create vault directory: %w", err)
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("vault: failed to create temp file: %w", err)
	}
	tmp := tmpFile.Name()

	_, writeErr := tmpFile.Write(data)
	closeErr := tmpFile.Close()
	if writeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: failed to write temp file: %w", writeErr)
	}
	if closeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: failed to write temp file: %w", closeErr)
	}
	if err := os.Chmod(tmp, filePerm); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: failed to set vault file permissions: %w", err)
	}

	// Retry the rename a few times: on Windows, MoveFileEx (which os.Rename
	// uses to replace an existing destination) briefly locks the destination
	// during the replace, so two goroutines renaming to the same path at
	// nearly the same instant can transiently fail with "Access is denied"
	// instead of one atomically winning as POSIX rename(2) would guarantee.
	// Last-rename-to-succeed-wins is still the intended behavior (see the
	// comment above); this just makes sure contention doesn't surface as a
	// spurious save failure.
	var renameErr error
	for attempt := 0; attempt < 5; attempt++ {
		if renameErr = os.Rename(tmp, path); renameErr == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	os.Remove(tmp)
	return fmt.Errorf("vault: failed to finalize vault file: %w", renameErr)
}
