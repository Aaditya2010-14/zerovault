package cli

import (
	"flag"
	"fmt"
	"time"

	"zerovault/internal/qrcode"
	"zerovault/internal/totp"
	"zerovault/internal/vault"
)

// cmd2FA dispatches "zerovault 2fa <subcommand>".
func cmd2FA(args []string) int {
	if len(args) == 0 {
		printError("usage: zerovault 2fa <enable|disable>")
		return 1
	}
	switch args[0] {
	case "enable":
		return cmd2FAEnable(args[1:])
	case "disable":
		return cmd2FADisable(args[1:])
	default:
		printError("unknown 2fa subcommand %q", args[0])
		return 1
	}
}

// setup2FA generates a fresh TOTP secret, shows it as both a QR code and
// plain text, and requires the caller to type back one currently-valid
// code before returning the secret — this catches a bad authenticator-app
// scan before it locks anyone out of their own vault.
func setup2FA() (string, error) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return "", err
	}

	uri := otpauthURI("vault", secret)
	m, err := qrcode.Encode([]byte(uri))
	if err != nil {
		return "", fmt.Errorf("cli: failed to generate QR code: %w", err)
	}

	printInfo("Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):")
	fmt.Print(qrcode.ToASCII(m))
	printInfo("Or enter this secret manually: %s", secret)

	code, err := ReadLine("Enter the 6-digit code from your app to confirm: ")
	if err != nil {
		return "", err
	}

	key, err := totp.DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	if !totp.Validate(key, code, time.Now(), totp.DefaultPeriod, totp.DefaultDigits, 1) {
		return "", fmt.Errorf("cli: code did not match — two-factor unlock was not enabled")
	}
	return secret, nil
}

func cmd2FAEnable(args []string) int {
	fs := flag.NewFlagSet("2fa enable", flag.ExitOnError)
	fs.Parse(args)

	v, path, masterPw, code := loadVaultInteractive()
	if code != 0 {
		return code
	}
	if v.TwoFAEnabled {
		printError("two-factor unlock is already enabled")
		return 1
	}

	secret, err := setup2FA()
	if err != nil {
		printError("%v", err)
		return 1
	}

	v.Enable2FA(secret)
	if err := vault.Save(path, masterPw, v); err != nil {
		printError("failed to save vault: %v", err)
		return 1
	}

	printSuccess("two-factor unlock enabled — future unlocks require your master password AND a TOTP code")
	return 0
}

func cmd2FADisable(args []string) int {
	fs := flag.NewFlagSet("2fa disable", flag.ExitOnError)
	fs.Parse(args)

	// loadVaultInteractive already demands a valid TOTP code when
	// v.TwoFAEnabled is true (see commands.go), so reaching this point
	// means both the master password and the current code checked out —
	// disabling 2FA itself requires 2FA.
	v, path, masterPw, code := loadVaultInteractive()
	if code != 0 {
		return code
	}
	if !v.TwoFAEnabled {
		printError("two-factor unlock is not enabled")
		return 1
	}

	v.Disable2FA()
	if err := vault.Save(path, masterPw, v); err != nil {
		printError("failed to save vault: %v", err)
		return 1
	}

	printSuccess("two-factor unlock disabled")
	return 0
}
