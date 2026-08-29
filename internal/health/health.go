// Package health analyzes a decrypted vault's password entries and
// produces a security health report: weak passwords, reused passwords,
// stale (never-rotated) passwords, and a per-entry strength score. Nothing
// here leaves plaintext passwords lying around longer than necessary —
// reuse detection compares SHA-256 hashes, not the passwords themselves.
package health

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"zerovault/internal/vault"
)

// Strength categorizes an entry's estimated bits of entropy.
type Strength int

const (
	Weak Strength = iota
	Fair
	Strong
	VeryStrong
)

func (s Strength) String() string {
	switch s {
	case Weak:
		return "Weak"
	case Fair:
		return "Fair"
	case Strong:
		return "Strong"
	default:
		return "Very Strong"
	}
}

// Classify maps entropy bits to a Strength band, per the thresholds in
// feature-expansion-instructions.md: <40 weak, 40-60 fair, 60-80 strong,
// 80+ very strong.
func Classify(bits float64) Strength {
	switch {
	case bits < 40:
		return Weak
	case bits < 60:
		return Fair
	case bits < 80:
		return Strong
	default:
		return VeryStrong
	}
}

// EntryHealth is one entry's computed strength.
type EntryHealth struct {
	Name     string
	Bits     float64
	Strength Strength
}

// Issue is a single finding, already formatted for display — reports are
// pure presentation of pre-computed Report data, matching the rest of the
// codebase's attack-logic/reporting split.
type Issue struct {
	Message string
}

// Report is the full health analysis of a vault at one point in time.
type Report struct {
	Score        int // 0-100
	Critical     []Issue
	Warning      []Issue
	Entries      []EntryHealth // every entry, for the strength breakdown
	AvgBits      float64
	OldestDays   int
	ReusedGroups int // number of distinct passwords reused across 2+ entries
}

const (
	staleAfter        = 90 * 24 * time.Hour
	criticalDeduction = 15
	warningDeduction  = 5
)

// Analyze inspects every password entry in v and produces a Report. now is
// passed in (rather than calling time.Now() internally) so age-based
// checks are deterministic in tests.
func Analyze(v *vault.Vault, now time.Time) Report {
	entries := v.List()

	var report Report
	hashGroups := map[[32]byte][]string{}

	for _, e := range entries {
		bits := entropyBits(e.Password)
		strength := Classify(bits)
		report.Entries = append(report.Entries, EntryHealth{Name: e.Name, Bits: bits, Strength: strength})
		report.AvgBits += bits

		hashGroups[sha256.Sum256([]byte(e.Password))] = append(hashGroups[sha256.Sum256([]byte(e.Password))], e.Name)

		if len(e.Password) < 8 {
			report.Critical = append(report.Critical, Issue{fmt.Sprintf("%s: password is shorter than 8 characters", e.Name)})
		}
		if isCommonPassword(e.Password) {
			report.Critical = append(report.Critical, Issue{fmt.Sprintf("%s: password is in common passwords list", e.Name)})
		}
		if IsBreached(e.Password) {
			report.Critical = append(report.Critical, Issue{fmt.Sprintf("%s: password appears in known breach databases", e.Name)})
		}
		if hasCommonPattern(e.Password) {
			report.Critical = append(report.Critical, Issue{fmt.Sprintf("%s: password contains a common pattern (123/abc/qwerty)", e.Name)})
		}
		if !hasUpper(e.Password) {
			report.Warning = append(report.Warning, Issue{fmt.Sprintf("%s: no uppercase letters in password", e.Name)})
		}
		if !hasDigit(e.Password) {
			report.Warning = append(report.Warning, Issue{fmt.Sprintf("%s: no numbers in password", e.Name)})
		}
		if !hasSymbol(e.Password) {
			report.Warning = append(report.Warning, Issue{fmt.Sprintf("%s: no symbols in password", e.Name)})
		}

		age := now.Sub(e.UpdatedAt)
		if age > staleAfter {
			days := int(age.Hours() / 24)
			if days > report.OldestDays {
				report.OldestDays = days
			}
			report.Warning = append(report.Warning, Issue{fmt.Sprintf("%s: password hasn't been changed in %d days", e.Name, days)})
		}
	}

	// Reused passwords: group by hash rather than plaintext.
	var reusedNames [][]string
	for _, names := range hashGroups {
		if len(names) > 1 {
			sort.Strings(names)
			reusedNames = append(reusedNames, names)
		}
	}
	sort.Slice(reusedNames, func(i, j int) bool { return reusedNames[i][0] < reusedNames[j][0] })
	report.ReusedGroups = len(reusedNames)
	for _, names := range reusedNames {
		report.Critical = append(report.Critical, Issue{fmt.Sprintf("%s: same password reused", strings.Join(names, ", "))})
	}

	if len(entries) > 0 {
		report.AvgBits /= float64(len(entries))
	}
	sort.Slice(report.Entries, func(i, j int) bool { return report.Entries[i].Name < report.Entries[j].Name })

	score := 100 - criticalDeduction*len(report.Critical) - warningDeduction*len(report.Warning)
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

// entropyBits estimates a password's entropy as length * log2(charset
// size), where charset size is the sum of the character classes actually
// present in the password (26 lower, 26 upper, 10 digits, 32 symbols) —
// the same estimate feature-expansion-instructions.md specifies.
func entropyBits(password string) float64 {
	if password == "" {
		return 0
	}
	charset := 0
	if hasLower(password) {
		charset += 26
	}
	if hasUpper(password) {
		charset += 26
	}
	if hasDigit(password) {
		charset += 10
	}
	if hasSymbol(password) {
		charset += 32
	}
	if charset == 0 {
		return 0
	}
	return float64(len(password)) * math.Log2(float64(charset))
}

func hasLower(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0
}
func hasUpper(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
}
func hasDigit(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
}
func hasSymbol(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) >= 0
}

var commonPatterns = []string{"123", "abc", "qwerty"}

func hasCommonPattern(password string) bool {
	lower := strings.ToLower(password)
	for _, p := range commonPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isCommonPassword(password string) bool {
	_, ok := commonPasswordSet[strings.ToLower(password)]
	return ok
}
