// Package vault defines the encrypted password vault's data model and
// in-memory CRUD operations. Encryption and disk persistence live in
// storage.go; this file only manipulates the decrypted, in-memory Vault.
package vault

import (
	"fmt"
	"sort"
	"time"

	"uuid"
)

// Entry is a single credential stored in the vault.
type Entry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password"`
	URL       string    `json:"url,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Vault is the decrypted, in-memory contents of a vault file: password
// entries and TOTP entries, both keyed by name within their own set.
type Vault struct {
	Version     int          `json:"version"`
	Entries     []*Entry     `json:"entries"`
	TOTPEntries []*TOTPEntry `json:"totp_entries"`
}

// New creates an empty vault.
func New() *Vault {
	return &Vault{Version: 1, Entries: []*Entry{}, TOTPEntries: []*TOTPEntry{}}
}

// Add inserts a new entry with a fresh UUID and returns it. name must be
// unique within the vault (case-sensitive) so lookups by name are
// unambiguous.
func (v *Vault) Add(name, username, password, url, notes string) (*Entry, error) {
	if name == "" {
		return nil, fmt.Errorf("vault: entry name cannot be empty")
	}
	if v.findByName(name) != nil {
		return nil, fmt.Errorf("vault: entry %q already exists", name)
	}

	now := time.Now().UTC()
	entry := &Entry{
		ID:        uuid.New().String(),
		Name:      name,
		Username:  username,
		Password:  password,
		URL:       url,
		Notes:     notes,
		CreatedAt: now,
		UpdatedAt: now,
	}
	v.Entries = append(v.Entries, entry)
	return entry, nil
}

// Get returns the entry with the given name, or an error if none exists.
func (v *Vault) Get(name string) (*Entry, error) {
	entry := v.findByName(name)
	if entry == nil {
		return nil, fmt.Errorf("vault: entry %q not found", name)
	}
	return entry, nil
}

// Delete removes the entry with the given name. It returns an error if no
// such entry exists.
func (v *Vault) Delete(name string) error {
	for i, e := range v.Entries {
		if e.Name == name {
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("vault: entry %q not found", name)
}

// Update modifies an existing entry's fields. Empty string arguments leave
// the corresponding field unchanged.
func (v *Vault) Update(name, username, password, url, notes string) (*Entry, error) {
	entry := v.findByName(name)
	if entry == nil {
		return nil, fmt.Errorf("vault: entry %q not found", name)
	}
	if username != "" {
		entry.Username = username
	}
	if password != "" {
		entry.Password = password
	}
	if url != "" {
		entry.URL = url
	}
	if notes != "" {
		entry.Notes = notes
	}
	entry.UpdatedAt = time.Now().UTC()
	return entry, nil
}

// List returns all entries sorted by name for stable, predictable output.
func (v *Vault) List() []*Entry {
	out := make([]*Entry, len(v.Entries))
	copy(out, v.Entries)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (v *Vault) findByName(name string) *Entry {
	for _, e := range v.Entries {
		if e.Name == name {
			return e
		}
	}
	return nil
}
