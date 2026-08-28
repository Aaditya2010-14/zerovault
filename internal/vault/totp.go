package vault

import (
	"fmt"
	"sort"
	"time"

	"uuid"

	"zerovault/internal/totp"
)

// TOTPEntry is a stored TOTP 2FA secret. Secret is kept Base32-encoded
// (the conventional provisioning format) rather than raw bytes so it
// round-trips through JSON as plain text.
type TOTPEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	Digits    int       `json:"digits"`
	Period    int       `json:"period"`
	CreatedAt time.Time `json:"created_at"`
}

// AddTOTP inserts a new TOTP entry. secret must be a valid Base32 string
// (as shown by an authenticator app's manual-entry setup screen).
func (v *Vault) AddTOTP(name, secret string, digits, period int) (*TOTPEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("vault: TOTP entry name cannot be empty")
	}
	if v.findTOTPByName(name) != nil {
		return nil, fmt.Errorf("vault: TOTP entry %q already exists", name)
	}
	if _, err := totp.DecodeSecret(secret); err != nil {
		return nil, err
	}
	if digits == 0 {
		digits = totp.DefaultDigits
	}
	if period == 0 {
		period = totp.DefaultPeriod
	}

	entry := &TOTPEntry{
		ID:        uuid.New().String(),
		Name:      name,
		Secret:    secret,
		Digits:    digits,
		Period:    period,
		CreatedAt: time.Now().UTC(),
	}
	v.TOTPEntries = append(v.TOTPEntries, entry)
	return entry, nil
}

// GetTOTP returns the TOTP entry with the given name.
func (v *Vault) GetTOTP(name string) (*TOTPEntry, error) {
	entry := v.findTOTPByName(name)
	if entry == nil {
		return nil, fmt.Errorf("vault: TOTP entry %q not found", name)
	}
	return entry, nil
}

// DeleteTOTP removes the TOTP entry with the given name.
func (v *Vault) DeleteTOTP(name string) error {
	for i, e := range v.TOTPEntries {
		if e.Name == name {
			v.TOTPEntries = append(v.TOTPEntries[:i], v.TOTPEntries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("vault: TOTP entry %q not found", name)
}

// ListTOTP returns all TOTP entries sorted by name.
func (v *Vault) ListTOTP() []*TOTPEntry {
	out := make([]*TOTPEntry, len(v.TOTPEntries))
	copy(out, v.TOTPEntries)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// CurrentCode generates the current TOTP code for this entry.
func (e *TOTPEntry) CurrentCode() (string, error) {
	key, err := totp.DecodeSecret(e.Secret)
	if err != nil {
		return "", err
	}
	return totp.GenerateTOTP(key, time.Now(), e.Period, e.Digits)
}

func (v *Vault) findTOTPByName(name string) *TOTPEntry {
	for _, e := range v.TOTPEntries {
		if e.Name == name {
			return e
		}
	}
	return nil
}
