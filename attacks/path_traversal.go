package attacks

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// --- ATTACK LOGIC ---

// scanTraversalCase is one malicious path submitted to POST /scanner —
// each tries to point the scanner at something outside the intended
// "scan my project" use case: OS-relative traversal, a Windows system
// path, the filesystem root, and an embedded NUL byte (a classic trick
// for truncating a path string in languages with C-style string handling
// — Go strings are length-prefixed so this shouldn't matter, but it's
// worth proving).
var scanTraversalCases = []string{
	"../../../etc/passwd",
	`C:\Windows\System32\config\SAM`,
	"/",
	"../../etc\x00/passwd",
}

// submitScanPath posts one path to the real /scanner endpoint on the live
// dashboard and returns the response status and body.
func submitScanPath(client *http.Client, baseURL, path string) (status int, body string, err error) {
	resp, err := client.PostForm(baseURL+"/scanner", url.Values{"path": {path}})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

// runPathTraversal fires each case in scanTraversalCases at the real
// dashboard and checks that validateScanPath (internal/web/security.go)
// rejected it — the response should render the scanner form again with
// an error, and never a findings table for an actual scan of the target.
func runPathTraversal(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[PATHTRAVERSAL] Starting path traversal attack...")

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
	rejected := 0
	for _, path := range scanTraversalCases {
		status, body, err := submitScanPath(client, ts.URL, path)
		ok := err == nil && status == http.StatusOK && !scanSucceeded(body)
		reportPathCase(w, path, status, ok, err)
		if ok {
			rejected++
		}
	}
	elapsed := time.Since(start)

	if rejected != len(scanTraversalCases) {
		return Result{StatusVulnerable, fmt.Sprintf("only %d/%d traversal attempts were blocked", rejected, len(scanTraversalCases)), elapsed}
	}
	return Result{StatusBlocked, "path traversal blocked", elapsed}
}

// scanSucceeded looks for the scanner page's "no secrets found" or
// findings-table markers to distinguish "path was rejected" from
// "path was accepted and actually scanned".
func scanSucceeded(body string) bool {
	return strings.Contains(body, "No secrets found.") || strings.Contains(body, "finding(s)")
}

// --- REPORTING ---

func reportPathCase(w io.Writer, path string, status int, ok bool, err error) {
	fmt.Fprintf(w, "[PATHTRAVERSAL] Path: %s\n", path)
	if err != nil {
		fmt.Fprintf(w, "[PATHTRAVERSAL]   request failed: %v\n", err)
		return
	}
	mark := "✗"
	if ok {
		mark = "✓"
	}
	fmt.Fprintf(w, "[PATHTRAVERSAL]   Response: %d — rejected before scanning %s\n", status, mark)
}
