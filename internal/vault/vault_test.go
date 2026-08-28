package vault

import "testing"

func TestVault_AddGet(t *testing.T) {
	v := New()
	entry, err := v.Add("github", "octocat", "hunter2", "https://github.com", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if entry.ID == "" {
		t.Fatalf("Add did not assign an ID")
	}

	got, err := v.Get("github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Password != "hunter2" {
		t.Fatalf("Get returned wrong password: %q", got.Password)
	}
}

func TestVault_AddDuplicateNameFails(t *testing.T) {
	v := New()
	if _, err := v.Add("github", "a", "b", "", ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := v.Add("github", "c", "d", "", ""); err == nil {
		t.Fatalf("expected error adding duplicate name")
	}
}

func TestVault_AddEmptyNameFails(t *testing.T) {
	v := New()
	if _, err := v.Add("", "a", "b", "", ""); err == nil {
		t.Fatalf("expected error adding empty name")
	}
}

func TestVault_GetMissingFails(t *testing.T) {
	v := New()
	if _, err := v.Get("nope"); err == nil {
		t.Fatalf("expected error getting missing entry")
	}
}

func TestVault_Delete(t *testing.T) {
	v := New()
	if _, err := v.Add("github", "a", "b", "", ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := v.Delete("github"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := v.Get("github"); err == nil {
		t.Fatalf("entry still present after Delete")
	}
}

func TestVault_DeleteMissingFails(t *testing.T) {
	v := New()
	if err := v.Delete("nope"); err == nil {
		t.Fatalf("expected error deleting missing entry")
	}
}

func TestVault_Update(t *testing.T) {
	v := New()
	if _, err := v.Add("github", "old-user", "old-pass", "", ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	updated, err := v.Update("github", "new-user", "", "", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Username != "new-user" {
		t.Fatalf("Update did not change username: %q", updated.Username)
	}
	if updated.Password != "old-pass" {
		t.Fatalf("Update changed password when empty string was passed: %q", updated.Password)
	}
}

func TestVault_ListSortedByName(t *testing.T) {
	v := New()
	for _, name := range []string{"zeta", "alpha", "mu"} {
		if _, err := v.Add(name, "u", "p", "", ""); err != nil {
			t.Fatalf("Add(%s): %v", name, err)
		}
	}
	list := v.List()
	if len(list) != 3 {
		t.Fatalf("got %d entries, want 3", len(list))
	}
	want := []string{"alpha", "mu", "zeta"}
	for i, e := range list {
		if e.Name != want[i] {
			t.Fatalf("List()[%d] = %q, want %q", i, e.Name, want[i])
		}
	}
}

func TestVault_AddAssignsUniqueIDs(t *testing.T) {
	v := New()
	e1, _ := v.Add("a", "u", "p", "", "")
	e2, _ := v.Add("b", "u", "p", "", "")
	if e1.ID == e2.ID {
		t.Fatalf("two entries got the same UUID: %s", e1.ID)
	}
}
