package attacks

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// --- ATTACK LOGIC ---

// noRedirectClient is a bare client with no cookies and no redirect
// following, so responses can be inspected exactly as the server sent
// them.
func noRedirectClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// getDashboard issues a real GET /dashboard, optionally with a specific
// cookie value substituted in place of a legitimate session token.
func getDashboard(baseURL, cookieValue string) (*http.Response, error) {
	client, err := noRedirectClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/dashboard", nil)
	if err != nil {
		return nil, err
	}
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "zerovault_session", Value: cookieValue})
	}
	return client.Do(req)
}

// runSessionSuite exercises five real session-handling paths against the
// live dashboard: no cookie, a forged random cookie, an unlock-then-lock
// cycle checking the old cookie is rejected, and inspection of the
// Set-Cookie header's HttpOnly flag.
func runSessionSuite(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[SESSION] Starting session security tests...")

	ts, err := startWebServer(h)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), 0}
	}
	defer ts.Close()

	start := time.Now()
	failures := 0

	// Test 1: no cookie at all.
	resp1, err1 := getDashboard(ts.URL, "")
	pass1 := reportSessionTest(w, 1, "No cookie → /dashboard", resp1, err1)
	if !pass1 {
		failures++
	}

	// Test 2: a fake, random-looking session token that was never issued.
	resp2, err2 := getDashboard(ts.URL, "0000000000000000000000000000000000000000000000000000000000000000")
	pass2 := reportSessionTest(w, 2, "Fake cookie → /dashboard", resp2, err2)
	if !pass2 {
		failures++
	}

	// Test 3: a syntactically-plausible but never-issued 64-hex-char token
	// (what an "expired" or guessed token looks like — the session store
	// has never seen it, which is indistinguishable from expired).
	resp3, err3 := getDashboard(ts.URL, "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef000000")
	pass3 := reportSessionTest(w, 3, "Unknown/expired session → /dashboard", resp3, err3)
	if !pass3 {
		failures++
	}

	// Test 4: unlock for real, lock, then try to reuse the pre-lock cookie.
	client, err := newAuthenticatedClient(ts, h.masterPw)
	if err != nil {
		return Result{StatusVulnerable, fmt.Sprintf("could not unlock dashboard: %v", err), time.Since(start)}
	}
	var sessionCookie *http.Cookie
	if u, err := url.Parse(ts.URL); err == nil {
		for _, c := range client.Jar.Cookies(u) {
			if c.Name == "zerovault_session" {
				sessionCookie = c
			}
		}
	}
	lockResp, err := client.Post(ts.URL+"/lock", "application/x-www-form-urlencoded", nil)
	if err == nil {
		lockResp.Body.Close()
	}
	var resp4 *http.Response
	var err4 error
	if sessionCookie != nil {
		resp4, err4 = getDashboard(ts.URL, sessionCookie.Value)
	}
	pass4 := reportSessionTest(w, 4, "Reuse cookie after /lock", resp4, err4)
	if !pass4 {
		failures++
	}

	// Test 5: HttpOnly flag on the Set-Cookie header from a fresh unlock.
	client2, err := noRedirectClient()
	httpOnly := false
	if err == nil {
		resp, uerr := client2.PostForm(ts.URL+"/unlock", url.Values{
			"password": {h.masterPw}, "confirm": {h.masterPw},
		})
		if uerr == nil {
			for _, c := range resp.Cookies() {
				if c.Name == "zerovault_session" && c.HttpOnly {
					httpOnly = true
				}
			}
			resp.Body.Close()
		}
	}
	reportHttpOnly(w, httpOnly)
	if !httpOnly {
		failures++
	}

	elapsed := time.Since(start)
	if failures > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d/5 session security checks failed", failures), elapsed}
	}
	return Result{StatusBlocked, "session security intact", elapsed}
}

// sessionTestPassed reports whether a session-guarded request was
// correctly rejected: redirected to /unlock (302/303).
func sessionTestPassed(resp *http.Response, err error) bool {
	if err != nil || resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther
}

// --- REPORTING ---

func reportSessionTest(w io.Writer, n int, label string, resp *http.Response, err error) bool {
	fmt.Fprintf(w, "[SESSION] Test %d: %s\n", n, label)
	if err != nil || resp == nil {
		fmt.Fprintf(w, "[SESSION]   request failed: %v\n", err)
		return false
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	ok := sessionTestPassed(resp, nil)
	mark := "✗"
	if ok {
		mark = "✓"
	}
	fmt.Fprintf(w, "[SESSION]   Response: %d → %s %s\n", resp.StatusCode, loc, mark)
	return ok
}

func reportHttpOnly(w io.Writer, httpOnly bool) {
	fmt.Fprintln(w, "[SESSION] Test 5: Cookie has HttpOnly flag")
	if httpOnly {
		fmt.Fprintln(w, "[SESSION]   Set-Cookie header contains HttpOnly: YES ✓")
	} else {
		fmt.Fprintln(w, "[SESSION]   Set-Cookie header contains HttpOnly: NO ✗")
	}
}
