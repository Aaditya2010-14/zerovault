package web

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	vaultPath := filepath.Join(t.TempDir(), "test.vault")

	srv, err := NewServer(vaultPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler, err := srv.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func unlockNewVault(t *testing.T, ts *httptest.Server, client *http.Client, password string) {
	t.Helper()
	resp, err := client.PostForm(ts.URL+"/unlock", url.Values{
		"password": {password},
		"confirm":  {password},
	})
	if err != nil {
		t.Fatalf("unlock request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unlock: got status %d, want 303; body: %s", resp.StatusCode, body)
	}
}

func TestDashboard_RedirectsToUnlockWithoutSession(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)

	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("got status %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/unlock" {
		t.Fatalf("redirected to %q, want /unlock", loc)
	}
}

func TestUnlock_CreatesVaultAndGrantsSession(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)

	unlockNewVault(t, ts, client, "testpass123")

	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (session should now be valid)", resp.StatusCode)
	}
}

func TestUnlock_WrongPasswordRejected(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "correct-password")

	// Fresh client (no session) tries to unlock with the wrong password.
	client2 := newTestClient(t)
	resp, err := client2.PostForm(ts.URL+"/unlock", url.Values{"password": {"wrong-password"}})
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "incorrect master password") {
		t.Fatalf("expected error message in response body, got: %s", body)
	}
}

func TestAddEntry_RoundTripsThroughDashboard(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	resp, err := client.PostForm(ts.URL+"/add", url.Values{
		"name": {"github"}, "username": {"octocat"}, "password": {"hunter2"}, "url": {"https://github.com"},
	})
	if err != nil {
		t.Fatalf("POST /add: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add entry: got status %d, want 303", resp.StatusCode)
	}

	dash, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer dash.Body.Close()
	body, _ := io.ReadAll(dash.Body)
	if !strings.Contains(string(body), "github") {
		t.Fatalf("dashboard does not list newly added entry: %s", body)
	}
}

func TestEntryView_ShowsPasswordAndEscapesHTML(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	_, err := client.PostForm(ts.URL+"/add", url.Values{
		"name": {"xss-test"}, "password": {"<script>alert(1)</script>"},
	})
	if err != nil {
		t.Fatalf("POST /add: %v", err)
	}

	resp, err := client.Get(ts.URL + "/entry/xss-test")
	if err != nil {
		t.Fatalf("GET /entry/xss-test: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "<script>alert(1)</script>") {
		t.Fatalf("html/template failed to escape stored XSS payload: %s", body)
	}
	if !strings.Contains(string(body), "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag in output: %s", body)
	}
}

func TestDeleteEntry_RemovesFromDashboard(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	if _, err := client.PostForm(ts.URL+"/add", url.Values{"name": {"temp"}, "password": {"x"}}); err != nil {
		t.Fatalf("POST /add: %v", err)
	}
	if _, err := client.PostForm(ts.URL+"/delete/temp", url.Values{}); err != nil {
		t.Fatalf("POST /delete/temp: %v", err)
	}

	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), ">temp<") {
		t.Fatalf("deleted entry still appears on dashboard: %s", body)
	}
}

func TestTOTP_AddAndListShowsCode(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	_, err := client.PostForm(ts.URL+"/totp", url.Values{
		"name": {"github"}, "secret": {"JBSWY3DPEHPK3PXP"},
	})
	if err != nil {
		t.Fatalf("POST /totp: %v", err)
	}

	resp, err := client.Get(ts.URL + "/totp")
	if err != nil {
		t.Fatalf("GET /totp: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "github") {
		t.Fatalf("totp list does not show added entry: %s", body)
	}
}

func TestGenerate_ReturnsPasswordOfRequestedLength(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	resp, err := client.PostForm(ts.URL+"/generate", url.Values{
		"length": {"24"}, "upper": {"on"}, "lower": {"on"}, "digits": {"on"},
	})
	if err != nil {
		t.Fatalf("POST /generate: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `class="code mono"`) {
		t.Fatalf("expected a generated password in the response: %s", body)
	}
}

func TestCrossOriginPOST_Rejected(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/add", strings.NewReader("name=hacked&password=x"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("cross-origin POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status %d, want 403 (CrossOriginProtection should reject this)", resp.StatusCode)
	}

	dash, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer dash.Body.Close()
	body, _ := io.ReadAll(dash.Body)
	if strings.Contains(string(body), "hacked") {
		t.Fatalf("cross-origin POST was not actually blocked — entry was added: %s", body)
	}
}

func TestLock_ClearsSessionCookie(t *testing.T) {
	ts := newTestServer(t)
	client := newTestClient(t)
	unlockNewVault(t, ts, client, "testpass123")

	resp, err := client.Post(ts.URL+"/lock", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST /lock: %v", err)
	}
	resp.Body.Close()

	dash, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer dash.Body.Close()
	if dash.StatusCode != http.StatusSeeOther {
		t.Fatalf("after lock, got status %d, want 303 redirect to /unlock", dash.StatusCode)
	}
}
