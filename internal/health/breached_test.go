package health

import (
	"testing"
	"time"

	"zerovault/internal/vault"
)

func TestIsBreached(t *testing.T) {
	if !IsBreached("password123") {
		t.Error("expected password123 to be flagged as breached")
	}
	if !IsBreached("qwerty123") {
		t.Error("expected qwerty123 to be flagged as breached")
	}
	if IsBreached("") {
		t.Error("empty string must never match")
	}
	if IsBreached("Xk9#mQ2$vL7pR4nW8zY1!bT6cJ3fH5dS") {
		t.Error("a long random string should not match the breach set")
	}
}

func TestAnalyzeFlagsBreachedPassword(t *testing.T) {
	v := vault.New()
	v.Add("test-site", "user", "password123", "", "")

	report := Analyze(v, time.Now())

	found := false
	for _, issue := range report.Critical {
		if issue.Message == "test-site: password appears in known breach databases" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a breach-database critical finding, got: %+v", report.Critical)
	}
}
