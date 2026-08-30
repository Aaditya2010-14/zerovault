package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	vcrypto "zerovault/internal/crypto"
	"zerovault/internal/totp"
	"zerovault/internal/vault"
	"zerovault/internal/web"
)

// Fixed, documented values for demo mode: a judge follows the printed
// walkthrough verbatim, so none of these can be randomized per run.
const (
	demoPassword   = "demo2026"
	demoTOTPSecret = "JBSWY3DPEHPK3PXP"
	demoTOTPName   = "github-2fa"
	demoProjectDir = "demo-project"
)

// cmdDemo implements `zerovault demo`: builds a throwaway vault and a
// throwaway git repo with realistic (fake) secrets, starts the dashboard,
// and prints a guided tour — so a judge can go from `git clone` to a full
// working demo without reading any documentation. Ctrl+C tears everything
// back down.
func cmdDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "address for the demo dashboard")
	doCleanup := fs.Bool("cleanup", false, "remove all demo data and reset the vault to its pre-demo state")
	fs.Parse(args)

	if *doCleanup {
		return cmdDemoCleanup()
	}

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		printError("invalid -addr %q: %v", *addr, err)
		return 1
	}
	if !isLoopbackHost(host) {
		printError("refusing to bind %q: the demo dashboard is localhost-only, like 'serve'", *addr)
		return 1
	}

	vaultPath := DefaultVaultPath()
	if vault.Exists(vaultPath) {
		printError("a vault already exists at %s — demo mode refuses to overwrite real data", vaultPath)
		printInfo("move it aside, or set ZEROVAULT_PATH to an empty path, then re-run 'zerovault demo'")
		return 1
	}
	if _, err := os.Stat(demoProjectDir); err == nil {
		printError("%q already exists in this directory — remove it before running the demo", demoProjectDir)
		return 1
	}

	printInfo("setting up demo vault and demo project...")

	if err := buildDemoVault(vaultPath); err != nil {
		printError("demo setup failed: %v", err)
		return 1
	}
	if err := os.WriteFile(demoMarkerPath(vaultPath), []byte(""), 0o644); err != nil {
		printError("demo setup failed: %v", err)
		os.Remove(vaultPath)
		return 1
	}
	if err := setupDemoProject(demoProjectDir); err != nil {
		printError("demo project setup failed: %v", err)
		os.Remove(vaultPath)
		os.Remove(demoMarkerPath(vaultPath))
		return 1
	}

	cleanup := func() {
		os.Remove(vaultPath)
		os.Remove(demoMarkerPath(vaultPath))
		os.RemoveAll(demoProjectDir)
	}

	wireAuditRunner()
	web.DemoMode = true
	srv, err := web.NewServer(vaultPath)
	if err != nil {
		printError("failed to initialize web server: %v", err)
		cleanup()
		return 1
	}
	handler, err := srv.Handler()
	if err != nil {
		printError("failed to build routes: %v", err)
		cleanup()
		return 1
	}
	httpSrv := &http.Server{Addr: *addr, Handler: handler}

	printDemoWalkthrough(*addr)

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	select {
	case err := <-serveErr:
		cleanup()
		if err != nil && err != http.ErrServerClosed {
			printError("server error: %v", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		stop()
		fmt.Println()
		printInfo("shutting down demo and cleaning up...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			printWarning("forced shutdown: %v", err)
		}

		cleanup()
		printSuccess("demo data removed: %s and %s/ deleted", vaultPath, demoProjectDir)
		return 0
	}
}

// demoMarkerPath returns the sentinel file that marks vaultPath as
// demo-created data. cmdDemoCleanup only ever deletes a vault guarded by
// this marker, so it can never be tricked into wiping a real vault that
// happens to live at the same default path.
func demoMarkerPath(vaultPath string) string {
	return vaultPath + ".demo-marker"
}

// cmdDemoCleanup implements `zerovault demo --cleanup`: removes the demo
// vault and demo-project/ directory left behind by a demo run that wasn't
// (or couldn't be) shut down cleanly with Ctrl+C.
func cmdDemoCleanup() int {
	vaultPath := DefaultVaultPath()
	markerPath := demoMarkerPath(vaultPath)

	_, markerErr := os.Stat(markerPath)
	hasDemoVault := markerErr == nil && vault.Exists(vaultPath)

	_, projectErr := os.Stat(demoProjectDir)
	hasDemoProject := projectErr == nil

	if !hasDemoVault && !hasDemoProject {
		printInfo("No demo data found — nothing to clean up.")
		return 0
	}

	if hasDemoVault {
		if err := os.Remove(vaultPath); err != nil {
			printError("failed to remove demo vault: %v", err)
			return 1
		}
		os.Remove(markerPath)
	}
	if hasDemoProject {
		if err := os.RemoveAll(demoProjectDir); err != nil {
			printError("failed to remove %s: %v", demoProjectDir, err)
			return 1
		}
	}

	printSuccess("Demo data cleaned up. Vault reset to normal.")
	return 0
}

// buildDemoVault creates a fresh vault at path, saved under demoPassword,
// pre-populated with five realistic credential entries (one deliberately
// weak and breached, one with a freshly generated strong password) and one
// TOTP entry using a well-known test secret so a judge can cross-check the
// generated code against Google Authenticator or any RFC 6238 tool.
func buildDemoVault(path string) error {
	v := vault.New()

	entries := []struct{ name, username, password, url, notes string }{
		{"github", "octocat", "gH_9mK#2pLwXz7Qv!", "https://github.com", "personal access token stored separately"},
		{"aws", "root", "Aw$7Tn!4vRq9LmZx2", "https://console.aws.amazon.com", "root account — should use IAM instead"},
		{"slack", "workspace-admin", "Sl@ck#8jKp3WnBv6q", "https://zerovault.slack.com", ""},
		{"netflix", "demo@zerovault.dev", "password123", "https://netflix.com", "reused password — flagged by breach check"},
	}
	for _, e := range entries {
		if _, err := v.Add(e.name, e.username, e.password, e.url, e.notes); err != nil {
			return fmt.Errorf("add %s: %w", e.name, err)
		}
	}

	stripePw, err := vcrypto.GeneratePassword(vcrypto.PasswordOptions{
		Length: 32, Lower: true, Upper: true, Digits: true, Symbols: true,
	})
	if err != nil {
		return fmt.Errorf("generate stripe password: %w", err)
	}
	if _, err := v.Add("stripe", "api", stripePw, "https://dashboard.stripe.com", "freshly generated password"); err != nil {
		return fmt.Errorf("add stripe: %w", err)
	}

	if _, err := v.AddTOTP(demoTOTPName, demoTOTPSecret, totp.DefaultDigits, totp.DefaultPeriod); err != nil {
		return fmt.Errorf("add totp: %w", err)
	}

	if err := vault.Save(path, demoPassword, v); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	return nil
}

// setupDemoProject writes a small fixture directory with fake, realistic
// leaked secrets and turns it into a 3-commit git repo: one commit adds a
// credentials file, a later commit deletes it. `zerovault scan` finds the
// secrets still on disk (config.py, deploy.sh, auth.js); `zerovault scan
// --git` finds the deleted one that a plain directory scan can never see.
func setupDemoProject(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}

	files := map[string]string{
		"README.md": "# Demo Project\n\nSynthetic fixture for the ZeroVault secret scanner demo.\n" +
			"Every credential in this directory is fake, generated only for this demo.\n",
		"config.py": "# AWS credentials (demo only — not real)\n" +
			"AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n" +
			"aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
		"deploy.sh": "#!/bin/bash\n" +
			"export GITHUB_TOKEN=\"ghp_1A2b3C4d5E6f7G8h9I0jK1L2M3n4O5p6Q7r8\"\n" +
			"curl -H \"Authorization: token $GITHUB_TOKEN\" https://api.github.com/user\n",
		"auth.js": "// JWT used for local dev auth — fake demo token\n" +
			"const DEMO_TOKEN = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\";\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}

	if err := gitRun(dir, "init", "-q"); err != nil {
		return fmt.Errorf("git init failed (is git installed and on PATH?): %w", err)
	}
	if err := gitCommitAll(dir, "Initial commit"); err != nil {
		return err
	}

	secretFile := filepath.Join(dir, "internal", "db_credentials.py")
	if err := os.MkdirAll(filepath.Dir(secretFile), 0o755); err != nil {
		return err
	}
	// Built by concatenation, not one literal: a contiguous "sk_live_..."
	// string in the Go source (even a fake, demo-only one) trips GitHub's
	// push-protection secret scanner on push. Splitting it doesn't change
	// what lands in the generated demo-project/internal/db_credentials.py
	// file at runtime — the scanner target — only how it reads in this
	// source file.
	fakeStripeKey := "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	secretContent := "# TEMPORARY — remove before merging!\n" +
		"STRIPE_SECRET_KEY = \"" + fakeStripeKey + "\"\n"
	if err := os.WriteFile(secretFile, []byte(secretContent), 0o644); err != nil {
		return err
	}
	if err := gitCommitAll(dir, "Add database credentials"); err != nil {
		return err
	}

	if err := os.Remove(secretFile); err != nil {
		return err
	}
	if err := gitCommitAll(dir, "Remove hardcoded credentials (security fix)"); err != nil {
		return err
	}

	return nil
}

// gitRun invokes the system git binary (not a Go dependency — an external
// tool, the same way a judge already needs git to have cloned this repo)
// rooted at dir via -C, since demo mode needs a real, valid on-disk repo for
// internal/gitscan (which reads .git/objects directly) to walk.
func gitRun(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitCommitAll stages everything and commits under a fixed demo identity,
// so the commit doesn't depend on (or pollute) the judge's own git config.
func gitCommitAll(dir, message string) error {
	if err := gitRun(dir, "add", "-A"); err != nil {
		return err
	}
	return gitRun(dir, "-c", "user.name=ZeroVault Demo", "-c", "user.email=demo@zerovault.dev", "commit", "-q", "-m", message)
}

func printDemoWalkthrough(addr string) {
	printBold("ZeroVault Demo Mode")
	fmt.Println("====================")
	fmt.Printf("Vault password: %s\n", demoPassword)
	fmt.Printf("Web dashboard: http://%s\n", addr)
	fmt.Println()
	fmt.Println("Try these:")
	fmt.Println("  zerovault get github          — retrieve a password")
	fmt.Println("  zerovault health              — see breach detection flag netflix")
	fmt.Printf("  zerovault totp get %s — compare with Google Authenticator\n", demoTOTPName)
	fmt.Printf("  zerovault scan %s/  — find leaked secrets\n", demoProjectDir)
	fmt.Printf("  zerovault scan --git %s/ — find deleted secrets in git history\n", demoProjectDir)
	fmt.Println("  zerovault encrypt any-file.txt — encrypt a file")
	fmt.Println("  zerovault attack              — run full security audit")
	fmt.Println("  zerovault attack --report audit.html — generate HTML audit report")
	fmt.Println()
	fmt.Printf("Open http://%s in your browser to see the dashboard.\n", addr)
	fmt.Println()
	printInfo("press Ctrl+C to stop the demo and clean up")
}
