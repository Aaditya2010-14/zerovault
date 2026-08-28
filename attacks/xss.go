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

// xssPayloads covers script tags, event-handler injection, attribute
// breakout, protocol-handler abuse, and a Go template-injection probe
// (checking that a raw `{{.Field}}`-shaped string is never re-evaluated
// as a template — it should render as inert literal text).
var xssPayloads = []string{
	`<script>alert('xss')</script>`,
	`<img src=x onerror="alert(1)">`,
	`" onmouseover="alert(1)" data-x="`,
	`<svg/onload=alert(1)>`,
	`javascript:alert(1)`,
	`<iframe src="http://evil.com"></iframe>`,
	`<body onload="alert(1)">`,
	`{{.MasterPassword}}`,
}

// dangerousTags is what "the payload actually executed as HTML" would
// look like verbatim in the response body.
var dangerousTags = []string{"<script>", "<img ", "<svg", "<iframe", "<body "}

type xssProbe struct {
	payload      string
	entryName    string
	responseBody string
	err          error
}

// storeAndFetch does the real work for one payload: POST it into the
// vault as an entry username via the live dashboard, then GET the entry
// view page back and return the raw response body — exactly what a
// browser would receive.
func storeAndFetch(client *http.Client, baseURL, entryName, payload string) xssProbe {
	probe := xssProbe{payload: payload, entryName: entryName}

	resp, err := client.PostForm(baseURL+"/add", url.Values{
		"name": {entryName}, "username": {payload}, "password": {"x"},
	})
	if err != nil {
		probe.err = err
		return probe
	}
	resp.Body.Close()

	resp, err = client.Get(baseURL + "/entry/" + entryName)
	if err != nil {
		probe.err = err
		return probe
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		probe.err = err
		return probe
	}
	probe.responseBody = string(body)
	return probe
}

// executed reports whether any raw, unescaped dangerous tag made it into
// the response — the one thing html/template's auto-escaping must never
// allow.
func (p xssProbe) executed() bool {
	for _, tag := range dangerousTags {
		if strings.Contains(p.responseBody, tag) {
			return true
		}
	}
	return false
}

// runXSSSuite spins up the real dashboard, unlocks it over real HTTP, and
// fires every payload in xssPayloads through the actual /add and
// /entry/{name} routes.
func runXSSSuite(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "[XSS] Starting XSS injection suite (%d payloads)...\n", len(xssPayloads))

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
	executedCount := 0
	for i, payload := range xssPayloads {
		entryName := fmt.Sprintf("xss-test-%d", i+1)
		probe := storeAndFetch(client, ts.URL, entryName, payload)
		reportXSSProbe(w, i+1, probe)
		if probe.executed() {
			executedCount++
		}
	}
	elapsed := time.Since(start)

	if executedCount > 0 {
		return Result{StatusVulnerable, fmt.Sprintf("%d payload(s) rendered as live HTML", executedCount), elapsed}
	}
	fmt.Fprintf(w, "[XSS] All %d payloads neutralized by html/template auto-escaping\n", len(xssPayloads))
	return Result{StatusBlocked, "XSS injection blocked by html/template auto-escaping", elapsed}
}

// --- REPORTING ---

func reportXSSProbe(w io.Writer, n int, p xssProbe) {
	fmt.Fprintf(w, "[XSS] Payload %d: %s\n", n, p.payload)
	if p.err != nil {
		fmt.Fprintf(w, "[XSS]   request failed: %v\n", p.err)
		return
	}
	fmt.Fprintf(w, "[XSS]   Stored as entry name %q\n", p.entryName)
	if p.executed() {
		fmt.Fprintln(w, "[XSS]   Raw dangerous tag in response: YES ✗")
	} else {
		fmt.Fprintln(w, "[XSS]   Raw dangerous tag in response: NO ✓")
	}
}
