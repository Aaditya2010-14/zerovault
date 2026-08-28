package vault

import "testing"

const testSecret = "JBSWY3DPEHPK3PXP" // valid base32, arbitrary test secret

func TestVault_AddGetTOTP(t *testing.T) {
	v := New()
	entry, err := v.AddTOTP("github", testSecret, 6, 30)
	if err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	if entry.ID == "" {
		t.Fatalf("AddTOTP did not assign an ID")
	}

	got, err := v.GetTOTP("github")
	if err != nil {
		t.Fatalf("GetTOTP: %v", err)
	}
	if got.Secret != testSecret {
		t.Fatalf("GetTOTP returned wrong secret")
	}
}

func TestVault_AddTOTP_DefaultsApplied(t *testing.T) {
	v := New()
	entry, err := v.AddTOTP("github", testSecret, 0, 0)
	if err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	if entry.Digits != 6 || entry.Period != 30 {
		t.Fatalf("AddTOTP defaults not applied: digits=%d period=%d", entry.Digits, entry.Period)
	}
}

func TestVault_AddTOTP_InvalidSecretFails(t *testing.T) {
	v := New()
	if _, err := v.AddTOTP("github", "not valid base32!!!", 6, 30); err == nil {
		t.Fatalf("expected error for invalid base32 secret")
	}
}

func TestVault_AddTOTP_DuplicateNameFails(t *testing.T) {
	v := New()
	if _, err := v.AddTOTP("github", testSecret, 6, 30); err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	if _, err := v.AddTOTP("github", testSecret, 6, 30); err == nil {
		t.Fatalf("expected error adding duplicate TOTP name")
	}
}

func TestVault_DeleteTOTP(t *testing.T) {
	v := New()
	if _, err := v.AddTOTP("github", testSecret, 6, 30); err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	if err := v.DeleteTOTP("github"); err != nil {
		t.Fatalf("DeleteTOTP: %v", err)
	}
	if _, err := v.GetTOTP("github"); err == nil {
		t.Fatalf("entry still present after DeleteTOTP")
	}
}

func TestVault_ListTOTPSortedByName(t *testing.T) {
	v := New()
	for _, name := range []string{"zeta", "alpha", "mu"} {
		if _, err := v.AddTOTP(name, testSecret, 6, 30); err != nil {
			t.Fatalf("AddTOTP(%s): %v", name, err)
		}
	}
	list := v.ListTOTP()
	want := []string{"alpha", "mu", "zeta"}
	for i, e := range list {
		if e.Name != want[i] {
			t.Fatalf("ListTOTP()[%d] = %q, want %q", i, e.Name, want[i])
		}
	}
}

func TestTOTPEntry_CurrentCode(t *testing.T) {
	v := New()
	entry, err := v.AddTOTP("github", testSecret, 6, 30)
	if err != nil {
		t.Fatalf("AddTOTP: %v", err)
	}
	code, err := entry.CurrentCode()
	if err != nil {
		t.Fatalf("CurrentCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("CurrentCode returned %d digits, want 6", len(code))
	}
}
