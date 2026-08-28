package attacks

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"

	"zerovault/internal/totp"
	"zerovault/internal/vault"
	"zerovault/internal/web"
)

// --- ATTACK LOGIC (fixture setup) ---
//
// These build the disposable vault and web server every attack runs
// against. They use the real vault and web packages exactly as the CLI
// and dashboard do — no shortcuts, no mocks.

// demoTOTPSecret is the RFC 6238 Appendix B / Google-Authenticator-style
// test secret ("12345678901234567890" in Base32) — a well-known, non-
// sensitive value used only inside this disposable fixture vault.
const demoTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// seedVault creates a small, realistic vault at h.vaultPath: a couple of
// password entries and one TOTP entry, saved (encrypted) under h.masterPw
// exactly the way `zerovault add` would.
func seedVault(h *Harness) error {
	v := vault.New()
	if _, err := v.Add("github", "octocat", "correct-horse-battery-staple", "https://github.com", ""); err != nil {
		return err
	}
	if _, err := v.Add("aws-prod", "admin", "Pr0d@ccessK3y#2026", "", ""); err != nil {
		return err
	}
	if _, err := v.AddTOTP("github-2fa", demoTOTPSecret, totp.DefaultDigits, totp.DefaultPeriod); err != nil {
		return err
	}
	return vault.Save(h.vaultPath, h.masterPw, v)
}

// startWebServer boots the real dashboard (same web.NewServer/.Handler()
// code path as `zerovault serve`) on an httptest.Server, so the web
// attacks send genuine HTTP requests over a real listener rather than
// calling handler functions directly.
func startWebServer(h *Harness) (*httptest.Server, error) {
	srv, err := web.NewServer(h.vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to construct web server: %w", err)
	}
	handler, err := srv.Handler()
	if err != nil {
		return nil, fmt.Errorf("failed to build routes: %w", err)
	}
	return httptest.NewServer(handler), nil
}

// newAuthenticatedClient unlocks the fixture vault over HTTP (a real
// POST /unlock, not a shortcut into session internals) and returns a
// client whose cookie jar now holds a valid session — the same state a
// real browser reaches after a user types the master password.
func newAuthenticatedClient(ts *httptest.Server, masterPw string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.PostForm(ts.URL+"/unlock", url.Values{
		"password": {masterPw},
		"confirm":  {masterPw},
	})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		return nil, fmt.Errorf("unlock failed: status %d", resp.StatusCode)
	}
	return client, nil
}
