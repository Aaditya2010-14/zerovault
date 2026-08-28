package vault

import (
	"fmt"
	"os"

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

// writeFileAtomic writes data to a temp file in the same directory as path
// and renames it into place, avoiding a truncated/corrupted vault file if
// the process is interrupted mid-write.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, filePerm); err != nil {
		return fmt.Errorf("vault: failed to write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vault: failed to finalize vault file: %w", err)
	}
	return nil
}
