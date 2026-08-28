// Package attacks is ZeroVault's own penetration-test suite: each file
// runs one real attack — actual PBKDF2/AES-GCM operations, actual HTTP
// requests against a running dashboard — against a disposable vault built
// fresh for the run. Nothing here touches the user's real vault at
// ~/.zerovault; runHarness below creates an isolated temp vault and, for
// the web attacks, an isolated httptest server.
//
// Every attack file is split into two clearly separate halves:
//   - ATTACK LOGIC: the real cryptographic operation or HTTP request. No
//     printing happens here — these functions return plain data.
//   - REPORTING: turns that data into the `[TAG] ...` console output.
//
// That split is deliberate: on camera, scrolling an attack file should
// show real crypto/HTTP code, not a wall of Printf calls.
package attacks

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Status is the outcome of one attack.
type Status int

const (
	// StatusBlocked means the attack was attempted and rejected by
	// ZeroVault's defenses (the expected outcome for nearly every attack
	// here).
	StatusBlocked Status = iota
	// StatusSecure means the attack looked for a weakness (a timing gap,
	// a repeated nonce) and found none.
	StatusSecure
	// StatusExpected means the attack "succeeded" in a way that is a
	// known, documented, and acceptable limitation (TOTP code space is
	// small; brute-forcing the 6-digit code is not the threat TOTP
	// defends against).
	StatusExpected
	// StatusVulnerable means the attack actually got through — this
	// should never appear in a passing run.
	StatusVulnerable
)

func (s Status) label() string {
	switch s {
	case StatusBlocked:
		return "✓ BLOCKED"
	case StatusSecure:
		return "✓ SECURE"
	case StatusExpected:
		return "ℹ EXPECTED"
	default:
		return "✗ VULNERABLE"
	}
}

// Result is what every attack's Run function returns: the reporting
// functions format Detail for the console, they never carry logic.
type Result struct {
	Status   Status
	Detail   string
	Duration time.Duration
}

// Attack pairs a named entry point with the harness it needs.
type Attack struct {
	Category string
	Name     string
	Run      func(h *Harness, w io.Writer) Result
}

// registry lists every attack in the order the report card presents them.
var registry = []Attack{
	{"CRYPTO ATTACKS", "Dictionary brute force (20 passwords)", runBruteForce},
	{"CRYPTO ATTACKS", "Vault bit-flip tampering (5 positions)", runBitFlipTamper},
	{"CRYPTO ATTACKS", "Vault truncation/injection (4 methods)", runTruncationTamper},
	{"CRYPTO ATTACKS", "PBKDF2 timing analysis", runTimingAnalysis},
	{"CRYPTO ATTACKS", "Nonce reuse detection (100 saves)", runNonceReuse},
	{"CRYPTO ATTACKS", "File encryption tampering (4 methods)", runFileTamperAttack},
	{"WEB ATTACKS", "XSS injection (8 payloads)", runXSSSuite},
	{"WEB ATTACKS", "CSRF cross-origin (5 origins)", runCSRFSuite},
	{"WEB ATTACKS", "Session security (5 vectors)", runSessionSuite},
	{"WEB ATTACKS", "Security headers verification", runHeadersCheck},
	{"WEB ATTACKS", "Path traversal (4 attempts)", runPathTraversal},
	{"TOTP ATTACKS", "TOTP code brute force", runTOTPBruteForce},
}

// Harness holds the disposable, per-run fixtures every attack shares: a
// temp vault with known contents and (lazily) a running web dashboard.
type Harness struct {
	dir           string
	vaultPath     string
	masterPw      string
	webBaseURL    string
	webCookieName string
}

func newHarness() (*Harness, func(), error) {
	dir, err := os.MkdirTemp("", "zerovault-attack-*")
	if err != nil {
		return nil, nil, err
	}
	h := &Harness{
		dir:       dir,
		vaultPath: filepath.Join(dir, "attack.vault"),
		masterPw:  "attack-suite-fixture-password",
	}
	cleanup := func() { os.RemoveAll(dir) }
	return h, cleanup, nil
}

// Report is the full run's results, in registry order, for the final
// scoreboard.
type Report struct {
	Results []namedResult
	Total   time.Duration
}

type namedResult struct {
	Category string
	Name     string
	Result   Result
}

// RunAll executes every attack in order, streaming per-attack progress to
// w, and returns the aggregate report used for the final scoreboard.
func RunAll(w io.Writer) (Report, error) {
	h, cleanup, err := newHarness()
	if err != nil {
		return Report{}, fmt.Errorf("attacks: failed to set up test fixtures: %w", err)
	}
	defer cleanup()

	if err := seedVault(h); err != nil {
		return Report{}, fmt.Errorf("attacks: failed to seed fixture vault: %w", err)
	}

	printBanner(w, len(registry))

	var report Report
	start := time.Now()
	lastCategory := ""
	for i, a := range registry {
		if a.Category != lastCategory {
			fmt.Fprintf(w, "\n%s\n", a.Category)
			lastCategory = a.Category
		}
		fmt.Fprintf(w, "  [%d/%d] %s...", i+1, len(registry), a.Name)

		res := a.Run(h, w)

		fmt.Fprintf(w, " %s (%s)\n", res.Status.label(), formatDuration(res.Duration))
		report.Results = append(report.Results, namedResult{a.Category, a.Name, res})
	}
	report.Total = time.Since(start)

	printScorecard(w, report)
	return report, nil
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
