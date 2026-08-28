package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// securityHeaders sets defense-in-depth HTTP headers on every response.
// None of these replace CrossOriginProtection or html/template escaping —
// they narrow what a browser will do if either of those is ever bypassed
// (e.g. framing, MIME sniffing, caching a password page).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		h.Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// --- Input validation ---
//
// These run server-side, in addition to (never instead of) html/template's
// auto-escaping on output. Rejecting malformed input here keeps bad data
// out of the vault file in the first place and gives the user a clear
// error instead of a confusing downstream failure.

var entryNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// validateEntryName enforces the name charset used to key vault entries.
// Restricting it to alphanumerics/hyphen/underscore means a name can never
// be mistaken for a path segment, even though names are never used as raw
// filesystem paths in this codebase — this is a belt-and-suspenders
// constraint, not a bypassable one.
func validateEntryName(name string) error {
	if !entryNameRE.MatchString(name) {
		return fmt.Errorf("entry name must be 1-64 characters: letters, digits, hyphens, underscores only")
	}
	return nil
}

const (
	maxUsernameLen = 256
	maxURLLen      = 2048
	maxNotesLen    = 8192
	maxPasswordLen = 64 * 1024
)

func validateFieldLen(field, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s is too long (max %d characters)", field, max)
	}
	return nil
}

// systemDirs are absolute paths the scanner refuses to walk from the web
// UI — scanning an entire OS volume is never the intent of a "scan my
// project for leaked secrets" tool, and it turns a slow mistake into a
// multi-hour one.
var systemDirs = map[string]bool{
	`c:\`:        true,
	`c:\windows`: true,
	`/`:          true,
	`/etc`:       true,
	`/root`:      true,
	`/sys`:       true,
	`/proc`:      true,
}

// validateScanPath rejects scan targets that don't exist, aren't
// directories, or are well-known system roots. It does not attempt to be
// an exhaustive path-traversal filter — the scanner only reads files (it
// never writes, executes, or returns raw file contents, only redacted
// matches), so the risk here is "accidentally scan way too much", not
// arbitrary file disclosure.
func validateScanPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("invalid path")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path")
	}
	clean := strings.ToLower(filepath.Clean(abs))
	if systemDirs[clean] {
		return fmt.Errorf("refusing to scan a system root directory")
	}

	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("directory not found")
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}
	return nil
}

// --- Rate limiting on /unlock ---
//
// The web UI has no separate account-lockout system, so this is the only
// thing standing between an attacker with local network access and an
// unthrottled PBKDF2 oracle. It is intentionally simple: a global counter,
// not per-IP, because the threat model already treats the loopback
// interface as a single trust boundary (see README).

type unlockLimiter struct {
	mu          sync.Mutex
	failures    int
	lockedUntil time.Time
}

func newUnlockLimiter() *unlockLimiter {
	return &unlockLimiter{}
}

// delay returns how long the caller must wait before this attempt is
// allowed to proceed, and records nothing by itself — call recordFailure
// or recordSuccess after the attempt resolves.
func (l *unlockLimiter) delay() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	if until := l.lockedUntil; until.After(time.Now()) {
		return time.Until(until)
	}
	if l.failures >= 5 {
		return 5 * time.Second
	}
	return 0
}

func (l *unlockLimiter) recordFailure() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.failures++
	if l.failures >= 10 {
		l.lockedUntil = time.Now().Add(60 * time.Second)
		l.failures = 0
	}
}

func (l *unlockLimiter) recordSuccess() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = 0
	l.lockedUntil = time.Time{}
}
