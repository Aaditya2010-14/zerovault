package attacks

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// --- ATTACK LOGIC ---

// headerExpectation is one security header this suite checks for, and a
// substring its value must contain to count as present and correct.
type headerExpectation struct {
	name         string
	mustContain  string
	whyItMatters string
}

var expectedHeaders = []headerExpectation{
	{"X-Content-Type-Options", "nosniff", "prevents MIME-type sniffing"},
	{"X-Frame-Options", "DENY", "prevents clickjacking via iframe embedding"},
	{"Content-Security-Policy", "default-src 'self'", "blocks inline/foreign script injection"},
	{"Referrer-Policy", "no-referrer", "stops URLs leaking via the Referer header"},
	{"Cache-Control", "no-store", "passwords are never cached by the browser"},
}

// runHeadersCheck fetches an authenticated /dashboard response over a
// real HTTP round trip and inspects the headers securityHeaders (see
// internal/web/security.go) is expected to set on every response.
func runHeadersCheck(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[HEADERS] Checking security headers...")

	ts, err := startWebServer(h)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), 0}
	}
	defer ts.Close()

	client, err := newAuthenticatedClient(ts, h.masterPw)
	if err != nil {
		return Result{StatusVulnerable, fmt.Sprintf("could not unlock dashboard: %v", err), 0}
	}

	start := time.Now()
	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		return Result{StatusVulnerable, fmt.Sprintf("request failed: %v", err), time.Since(start)}
	}
	resp.Body.Close()
	elapsed := time.Since(start)

	missing := 0
	for _, exp := range expectedHeaders {
		got := resp.Header.Get(exp.name)
		present := strings.Contains(got, exp.mustContain)
		reportHeaderCheck(w, exp, got, present)
		if !present {
			missing++
		}
	}

	if missing > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d/%d security headers missing or wrong", missing, len(expectedHeaders)), elapsed}
	}
	return Result{StatusBlocked, "all security headers present and correct", elapsed}
}

// --- REPORTING ---

func reportHeaderCheck(w io.Writer, exp headerExpectation, got string, present bool) {
	mark := "✗"
	if present {
		mark = "✓"
	}
	if got == "" {
		got = "(missing)"
	}
	fmt.Fprintf(w, "[HEADERS] %s: %s %s\n", exp.name, got, mark)
}
