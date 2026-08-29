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
	"sync"
	"time"
)

// Version is ZeroVault's version string, shown in the attack report header.
const Version = "1.0.0"

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

// Label returns the human-readable status string shown in reports.
func (s Status) Label() string {
	return s.label()
}

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

// Attack pairs a named entry point with the harness it needs. Description
// and Methodology are presentation metadata (used by the HTML report and
// the web /audit page) — they don't affect what the attack actually does.
type Attack struct {
	Category    string
	Name        string
	Description string // what the attack does and why it should fail
	Methodology string // 1-2 sentences on the technique
	Run         func(h *Harness, w io.Writer) Result
}

// registry lists every attack in the order the report card presents them.
var registry = []Attack{
	{"CRYPTO ATTACKS", "Dictionary brute force (20 passwords)",
		"Attempts to unlock the fixture vault using 20 of the most common leaked passwords, none of which is the vault's real password.",
		"Each guess runs the full PBKDF2-HMAC-SHA256 derivation (100,000 iterations) the vault actually uses, then attempts AES-GCM decryption — measuring real-world guess cost, not a shortcut.",
		runBruteForce},
	{"CRYPTO ATTACKS", "Vault bit-flip tampering (5 positions)",
		"Flips a single bit at five different offsets in an encrypted vault file (nonce, early/mid/late ciphertext, auth tag) and attempts to decrypt each.",
		"AES-GCM is authenticated encryption: any single-bit change anywhere in the sealed data must make the GCM authentication tag check fail, causing decryption to be rejected outright rather than returning corrupted plaintext.",
		runBitFlipTamper},
	{"CRYPTO ATTACKS", "Vault truncation/injection (4 methods)",
		"Truncates the auth tag, truncates the ciphertext, keeps only the header, and appends garbage bytes to a real vault file, then attempts to decrypt each mutation.",
		"GCM's tag covers the entire ciphertext length; truncating or extending the sealed data changes what the tag was computed over, so verification must fail for every mutation.",
		runTruncationTamper},
	{"CRYPTO ATTACKS", "PBKDF2 timing analysis",
		"Measures key-derivation time for passwords of very different lengths (1 char, 8 chars, 50 chars) to look for a timing side-channel that could leak password length.",
		"PBKDF2's iteration count dominates its cost regardless of input length, so derivation time should stay flat across password lengths; a large variance would suggest an exploitable timing leak.",
		runTimingAnalysis},
	{"CRYPTO ATTACKS", "Nonce reuse detection (100 saves)",
		"Saves the vault 100 times in a row and records every AES-GCM nonce used, checking for any repeat.",
		"AES-GCM security depends entirely on never reusing a (key, nonce) pair; each save draws a fresh 12-byte nonce from crypto/rand, so 100 saves should produce 100 distinct nonces.",
		runNonceReuse},
	{"CRYPTO ATTACKS", "File encryption tampering (4 methods)",
		"Encrypts a real file with zerovault's file-encryption pipeline, then flips a ciphertext bit, truncates the final chunk, appends trailing garbage, and corrupts a chunk-length prefix.",
		"Each 64KB chunk is sealed under its own nonce with the chunk's length and last-chunk status bound into the authentication, so any of these four mutations must be rejected before any plaintext is written.",
		runFileTamperAttack},
	{"WEB ATTACKS", "XSS injection (8 payloads)",
		"Submits 8 classic XSS payloads (script tags, event-handler injection, attribute breakout, protocol handlers, a Go template-injection probe) as an entry's username through the live dashboard, then inspects the rendered response.",
		"html/template auto-escapes by output context, so every payload should come back as inert escaped text (or, for the template-injection probe, unevaluated literal text) — never as live, executable markup.",
		runXSSSuite},
	{"WEB ATTACKS", "CSRF cross-origin (5 origins)",
		"Sends mutating POST requests (add entry, delete entry) from 5 different cross-origin contexts (evil.com, wrong port, wrong scheme, no Origin header, sandboxed iframe) against an authenticated session.",
		"net/http's CrossOriginProtection rejects any request whose Sec-Fetch-Site/Origin doesn't match the server's own origin, so all 5 forged requests should be blocked with 403 while the same-origin control request succeeds.",
		runCSRFSuite},
	{"WEB ATTACKS", "Session security (5 vectors)",
		"Requests the authenticated dashboard with no cookie, a fake random cookie, an unknown/expired session, and a cookie reused after explicit logout — plus checks the session cookie's own flags.",
		"Every protected route runs through requireSession, which redirects to /unlock unless a live, unexpired server-side session exists; the cookie itself is also checked for the HttpOnly flag that keeps it invisible to JavaScript.",
		runSessionSuite},
	{"WEB ATTACKS", "Security headers verification",
		"Fetches an authenticated dashboard page and inspects the response headers for the standard browser-side hardening set.",
		"X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Referrer-Policy, and Cache-Control are all set unconditionally by internal/web/security.go's middleware, so they must appear on every response.",
		runHeadersCheck},
	{"WEB ATTACKS", "Path traversal (4 attempts)",
		"Submits 4 path-traversal-style inputs (../../../etc/passwd, a Windows SAM path, root, and a spaced traversal) to the secrets scanner's path field.",
		"The scanner validates and normalizes the target path before ever touching the filesystem, so a traversal attempt should be rejected as an ordinary invalid path rather than actually being scanned.",
		runPathTraversal},
	{"TOTP ATTACKS", "TOTP code brute force",
		"Brute-forces the full 000000-999999 keyspace looking for the currently valid 6-digit TOTP code, without knowing the underlying secret.",
		"This attack is expected to eventually succeed — TOTP's security model relies on the secret being unknown, not the 6-digit code space (1 million possibilities) being unguessable; real services pair TOTP with attempt-rate limiting, which this suite documents rather than re-implements.",
		runTOTPBruteForce},
	{"TOTP ATTACKS", "Vault 2FA unlock bypass (3 vectors)",
		"Against a disposable vault with two-factor unlock enabled: tries to reach the dashboard with the master password alone, then with the master password plus a wrong TOTP code, then confirms the master password plus the correct code actually works.",
		"Exercises the real /unlock and /unlock/2fa HTTP endpoints and session cookies exactly as a browser would, checking that no combination short of both correct factors ever yields a session cookie or dashboard access.",
		runVaultTwoFAUnlock},
}

// Registry returns the list of every attack this suite runs, including
// their Description/Methodology presentation metadata — used by the web
// /audit page and the HTML report to describe each test.
func Registry() []Attack {
	return registry
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

// lastReport caches the most recent completed run so both the CLI (for
// -report) and the web /audit handler can access the same result without
// re-running the suite. Guarded by lastReportMu since the web handler can
// be hit concurrently.
var (
	lastReportMu sync.RWMutex
	lastReport   *Report
	lastReportAt time.Time
)

// LastReport returns the most recently completed run's report and the time
// it finished, or ok=false if no run has completed yet in this process.
func LastReport() (report Report, at time.Time, ok bool) {
	lastReportMu.RLock()
	defer lastReportMu.RUnlock()
	if lastReport == nil {
		return Report{}, time.Time{}, false
	}
	return *lastReport, lastReportAt, true
}

func setLastReport(r Report) {
	lastReportMu.Lock()
	defer lastReportMu.Unlock()
	cp := r
	lastReport = &cp
	lastReportAt = time.Now()
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
	setLastReport(report)
	return report, nil
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
