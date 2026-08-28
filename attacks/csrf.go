package attacks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// --- ATTACK LOGIC ---

// crossOriginCase is one forged request: a valid session cookie (stolen,
// say, via an unrelated bug) paired with headers a real cross-site page
// would send. net/http's CrossOriginProtection inspects Sec-Fetch-Site
// first and falls back to comparing Origin against the request's own
// Host, so both header shapes are exercised here.
type crossOriginCase struct {
	label  string
	method string
	path   string
	body   string
	origin string
	// secFetchSite, when set, simulates the header modern browsers send
	// automatically and that CrossOriginProtection checks first.
	secFetchSite string
}

var crossOriginCases = []crossOriginCase{
	{"Origin=http://evil-site.com", http.MethodPost, "/add", "name=hacked1&password=x", "http://evil-site.com", "cross-site"},
	{"Origin=wrong port", http.MethodPost, "/add", "name=hacked2&password=x", "http://127.0.0.1:9999", "cross-site"},
	{"Origin=wrong scheme", http.MethodPost, "/add", "name=hacked3&password=x", "https://127.0.0.1", "cross-site"},
	{"No Origin header, cross-site fetch", http.MethodPost, "/add", "name=hacked4&password=x", "", "cross-site"},
	{"Origin=null (sandboxed iframe)", http.MethodPost, "/delete/github", "", "null", "cross-site"},
}

// sendCrossOrigin issues one real HTTP request carrying the session
// cookie from client's jar but attacker-controlled Origin/Sec-Fetch-Site
// headers — this is what a malicious page's fetch()/form-submit would
// produce.
func sendCrossOrigin(client *http.Client, baseURL string, c crossOriginCase) (*http.Response, error) {
	req, err := http.NewRequest(c.method, baseURL+c.path, strings.NewReader(c.body))
	if err != nil {
		return nil, err
	}
	if c.body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.secFetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", c.secFetchSite)
	}
	return client.Do(req)
}

// runCSRFSuite fires every forged cross-origin request in
// crossOriginCases at the real dashboard, then sends one legitimate
// same-origin request as a control to confirm the protection isn't just
// blocking everything indiscriminately.
func runCSRFSuite(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[CSRF] Starting CSRF attack suite...")

	ts, err := startWebServer(h)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), 0}
	}
	defer ts.Close()

	client, err := newAuthenticatedClient(ts, h.masterPw)
	if err != nil {
		return Result{StatusVulnerable, fmt.Sprintf("could not unlock dashboard: %v", err), 0}
	}
	fmt.Fprintln(w, "[CSRF] Session obtained ✓")

	start := time.Now()
	blocked := 0
	for _, c := range crossOriginCases {
		resp, err := sendCrossOrigin(client, ts.URL, c)
		status := 0
		if err == nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		reportCSRFCase(w, c, status, err)
		if status == http.StatusForbidden {
			blocked++
		}
	}

	// Control: a same-origin request with matching Origin must succeed —
	// proves CrossOriginProtection discriminates by origin instead of
	// rejecting every POST.
	controlResp, err := sendCrossOrigin(client, ts.URL, crossOriginCase{
		label: "control", method: http.MethodPost, path: "/add",
		body: "name=legit-control-entry&password=x", origin: ts.URL, secFetchSite: "same-origin",
	})
	controlStatus := 0
	if err == nil {
		controlStatus = controlResp.StatusCode
		controlResp.Body.Close()
	}
	reportCSRFControl(w, controlStatus, err)
	elapsed := time.Since(start)

	if blocked != len(crossOriginCases) {
		return Result{StatusVulnerable, fmt.Sprintf("only %d/%d forged requests were blocked", blocked, len(crossOriginCases)), elapsed}
	}
	if controlStatus != http.StatusOK && controlStatus != http.StatusSeeOther {
		return Result{StatusVulnerable, "legitimate same-origin request was also blocked", elapsed}
	}

	fmt.Fprintf(w, "[CSRF] All %d cross-origin attacks blocked, legitimate request accepted\n", len(crossOriginCases))
	return Result{StatusBlocked, "CSRF protection (net/http.CrossOriginProtection) working", elapsed}
}

// --- REPORTING ---

func reportCSRFCase(w io.Writer, c crossOriginCase, status int, err error) {
	fmt.Fprintf(w, "[CSRF] Attack: %s → %s %s\n", c.label, c.method, c.path)
	if err != nil {
		fmt.Fprintf(w, "[CSRF]   request failed: %v\n", err)
		return
	}
	mark := "✗"
	if status == http.StatusForbidden {
		mark = "✓"
	}
	fmt.Fprintf(w, "[CSRF]   Response: %d %s\n", status, mark)
}

func reportCSRFControl(w io.Writer, status int, err error) {
	fmt.Fprintln(w, "[CSRF] Control: same-origin → POST /add")
	if err != nil {
		fmt.Fprintf(w, "[CSRF]   request failed: %v\n", err)
		return
	}
	fmt.Fprintf(w, "[CSRF]   Response: %d (legitimate request accepted)\n", status)
}
