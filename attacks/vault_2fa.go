package attacks

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"zerovault/internal/totp"
	"zerovault/internal/vault"
	"zerovault/internal/web"
)

// twoFAAttackSecret is another well-known, non-sensitive demo secret,
// distinct from demoTOTPSecret in fixtures.go so this attack's dedicated
// vault doesn't share state with the rest of the suite.
const twoFAAttackSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func noFollowClient() (*http.Client, *cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, jar, nil
}

func hasCookieNamed(jar *cookiejar.Jar, target *url.URL, name string) bool {
	for _, c := range jar.Cookies(target) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// runVaultTwoFAUnlock stands up its own disposable vault with 2FA enabled
// (separate from the shared fixture vault, so this suite's other TOTP
// attack doesn't interact with it) and, over real HTTP against a real
// running dashboard, checks the three properties vault-level 2FA is
// supposed to guarantee: password alone is not enough, password plus a
// wrong code is not enough, and password plus the correct code works.
func runVaultTwoFAUnlock(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2FA] Setting up a disposable vault with two-factor unlock enabled...")
	start := time.Now()

	dir, err := os.MkdirTemp("", "zerovault-2fa-*")
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	defer os.RemoveAll(dir)

	vaultPath := filepath.Join(dir, "2fa.vault")
	masterPw := "attack-2fa-fixture-password"

	v := vault.New()
	v.Enable2FA(twoFAAttackSecret)
	if err := vault.Save(vaultPath, masterPw, v); err != nil {
		return Result{StatusVulnerable, "failed to seed 2FA fixture vault: " + err.Error(), time.Since(start)}
	}

	srv, err := web.NewServer(vaultPath)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	handler, err := srv.Handler()
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}

	// --- Test 1: password alone must NOT unlock the vault. ---
	fmt.Fprintln(w, "[2FA] Test 1: password only (no code)...")
	client, jar, err := noFollowClient()
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	resp, err := client.PostForm(ts.URL+"/unlock", url.Values{"password": {masterPw}})
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther || hasCookieNamed(jar, tsURL, "zerovault_session") {
		return Result{StatusVulnerable, "password alone unlocked a 2FA-protected vault", time.Since(start)}
	}
	fmt.Fprintln(w, "[2FA]   correctly held at the code step, no session cookie issued")

	// --- Test 2: password + wrong code must NOT unlock the vault. ---
	fmt.Fprintln(w, "[2FA] Test 2: password + wrong code...")
	resp, err = client.PostForm(ts.URL+"/unlock/2fa", url.Values{"code": {"000000"}})
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther || hasCookieNamed(jar, tsURL, "zerovault_session") {
		return Result{StatusVulnerable, "an incorrect TOTP code unlocked a 2FA-protected vault", time.Since(start)}
	}
	dashResp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	dashResp.Body.Close()
	if dashResp.StatusCode != http.StatusSeeOther {
		return Result{StatusVulnerable, "dashboard was reachable after a wrong 2FA code", time.Since(start)}
	}
	fmt.Fprintln(w, "[2FA]   correctly rejected, dashboard still locked")

	// --- Test 3: password + correct code MUST unlock the vault. ---
	fmt.Fprintln(w, "[2FA] Test 3: password + correct code...")
	key, err := totp.DecodeSecret(twoFAAttackSecret)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	code, err := totp.GenerateTOTP(key, time.Now(), totp.DefaultPeriod, totp.DefaultDigits)
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	resp, err = client.PostForm(ts.URL+"/unlock/2fa", url.Values{"code": {code}})
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !hasCookieNamed(jar, tsURL, "zerovault_session") {
		return Result{StatusVulnerable, "the correct master password + correct TOTP code failed to unlock the vault", time.Since(start)}
	}
	dashResp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		return Result{StatusVulnerable, err.Error(), time.Since(start)}
	}
	dashResp.Body.Close()
	if dashResp.StatusCode != http.StatusOK {
		return Result{StatusVulnerable, "dashboard was not reachable after a fully correct 2FA unlock", time.Since(start)}
	}
	fmt.Fprintln(w, "[2FA]   correctly unlocked with both factors present")

	elapsed := time.Since(start)
	return Result{StatusBlocked, "password-only and wrong-code unlocks rejected; correct password+code unlocks", elapsed}
}
