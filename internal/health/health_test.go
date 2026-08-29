package health

import (
	"strings"
	"testing"
	"time"

	"zerovault/internal/vault"
)

func addAt(t *testing.T, v *vault.Vault, name, password string, updatedAt time.Time) {
	t.Helper()
	e, err := v.Add(name, "", password, "", "")
	if err != nil {
		t.Fatalf("add %q: %v", name, err)
	}
	e.UpdatedAt = updatedAt
}

func TestWeakPasswordDetected(t *testing.T) {
	v := vault.New()
	now := time.Now()
	addAt(t, v, "site", "password", now)

	r := Analyze(v, now)
	if len(r.Critical) == 0 {
		t.Fatal("expected at least one critical issue for a common password")
	}
	found := false
	for _, e := range r.Entries {
		if e.Name == "site" && e.Strength == Weak {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'site' entry to be classified Weak")
	}
}

func TestReuseDetected(t *testing.T) {
	v := vault.New()
	now := time.Now()
	addAt(t, v, "a", "SameP@ssw0rd!123", now)
	addAt(t, v, "b", "SameP@ssw0rd!123", now)
	addAt(t, v, "c", "Different#Pass99", now)

	r := Analyze(v, now)
	foundReuse := false
	for _, issue := range r.Critical {
		if strings.Contains(issue.Message, "a, b") && strings.Contains(issue.Message, "reused") {
			foundReuse = true
		}
	}
	if !foundReuse {
		t.Fatalf("expected reuse issue mentioning 'a, b', got: %+v", r.Critical)
	}
}

func TestAgeDetection(t *testing.T) {
	v := vault.New()
	now := time.Now()
	addAt(t, v, "old", "Str0ng&Unique!Pass1", now.Add(-100*24*time.Hour))
	addAt(t, v, "fresh", "An0ther&Unique!Pass2", now.Add(-1*24*time.Hour))

	r := Analyze(v, now)
	foundOld := false
	for _, issue := range r.Warning {
		if strings.Contains(issue.Message, "old:") && strings.Contains(issue.Message, "100 days") {
			foundOld = true
		}
	}
	if !foundOld {
		t.Fatalf("expected age warning for 'old' entry (100 days), got: %+v", r.Warning)
	}
	for _, issue := range r.Warning {
		if strings.Contains(issue.Message, "fresh:") && strings.Contains(issue.Message, "days") {
			t.Fatalf("did not expect an age warning for a 1-day-old password: %s", issue.Message)
		}
	}
}

func TestStrengthScoring(t *testing.T) {
	cases := []struct {
		password string
		want     Strength
	}{
		{"abc", Weak},
		{"password", Weak},
		{"Abcdefgh12", Fair},
		{"Abcdefg1!@#", Strong},
		{"Abcdefghij12!@#$%^&*XYZ", VeryStrong},
	}
	for _, c := range cases {
		bits := entropyBits(c.password)
		got := Classify(bits)
		if got != c.want {
			t.Errorf("entropyBits(%q)=%.1f classified as %s, want %s", c.password, bits, got, c.want)
		}
	}
}

func TestPerfectScore(t *testing.T) {
	v := vault.New()
	now := time.Now()
	addAt(t, v, "one", "Xk9$mQ2!vLp8&Wz3Rd", now)
	addAt(t, v, "two", "Yn7#tRz5!Bq4&Fx1Ck", now)

	r := Analyze(v, now)
	if r.Score != 100 {
		t.Fatalf("expected a perfect 100 score for strong, unique, recent passwords, got %d (critical=%v warning=%v)",
			r.Score, r.Critical, r.Warning)
	}
}
