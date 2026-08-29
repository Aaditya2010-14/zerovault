package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vcrypto "zerovault/internal/crypto"
	"zerovault/internal/totp"
	"zerovault/internal/vault"
)

// DefaultVaultPath returns the default vault file location:
// $HOME/.zerovault/vault.db, overridable with the ZEROVAULT_PATH env var.
func DefaultVaultPath() string {
	if p := os.Getenv("ZEROVAULT_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".zerovault", "vault.db")
}

// Run dispatches a CLI invocation. args is os.Args[1:].
func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "add":
		return cmdAdd(args[1:])
	case "get":
		return cmdGet(args[1:])
	case "list":
		return cmdList(args[1:])
	case "delete":
		return cmdDelete(args[1:])
	case "generate":
		return cmdGenerate(args[1:])
	case "totp":
		return cmdTOTP(args[1:])
	case "scan":
		return cmdScan(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "attack":
		return cmdAttack(args[1:])
	case "encrypt":
		return cmdEncrypt(args[1:])
	case "decrypt":
		return cmdDecrypt(args[1:])
	case "health":
		return cmdHealth(args[1:])
	case "rekey":
		return cmdRekey(args[1:])
	case "2fa":
		return cmd2FA(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		printError("unknown command %q", args[0])
		printUsage()
		return 1
	}
}

func printUsage() {
	printBold("ZeroVault — zero-dependency security toolkit")
	fmt.Println(`
Usage:
  zerovault init [--2fa]                  create a new vault (optionally with 2FA unlock)
  zerovault add [options] <name>          add a credential entry
  zerovault get [-copy] <name>            retrieve a credential entry
  zerovault list                          list all entry names
  zerovault delete <name>                 delete an entry
  zerovault generate [options]            generate a random password
  zerovault totp add [-digits N] [-period N] <name>   add a TOTP 2FA secret
  zerovault totp get <name>               show the current TOTP code
  zerovault totp list                     list all TOTP entries with live codes
  zerovault scan [options] <path>         scan a directory for leaked secrets
  zerovault scan --git <repo> [-depth N]  scan git commit history for leaked secrets
  zerovault serve [-addr host:port]       start the web dashboard
  zerovault attack                        run the built-in security audit (penetration test suite)
  zerovault encrypt <file> [-o out.enc]   encrypt any file with AES-256-GCM
  zerovault decrypt <file.enc> [-o out]   decrypt a ZeroVault-encrypted file
  zerovault health                        print a vault password health report
  zerovault rekey                         change the vault's master password
  zerovault 2fa enable                    enable TOTP two-factor unlock for the vault
  zerovault 2fa disable                   disable two-factor unlock (requires a valid code)

Note: flags must come before the entry name.

Scan options:
  -min-entropy float   entropy threshold for generic secret detection (default 3.5)

Add options:
  -username string   account username
  -url string        associated URL
  -notes string       free-text notes
  -generate           generate a random password instead of prompting
  -length int         generated password length (default 20)

Environment:
  ZEROVAULT_PATH      override the default vault file location`)
}

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	enable2FA := fs.Bool("2fa", false, "enable TOTP two-factor unlock for this vault")
	fs.Parse(args)

	path := DefaultVaultPath()
	if vault.Exists(path) {
		printError("vault already exists at %s", path)
		return 1
	}

	pw1, err := ReadPassword("Set master password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	pw2, err := ReadPassword("Confirm master password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	if pw1 != pw2 {
		printError("passwords do not match")
		return 1
	}
	if pw1 == "" {
		printError("master password cannot be empty")
		return 1
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		printError("failed to create vault directory: %v", err)
		return 1
	}

	v := vault.New()
	if *enable2FA {
		secret, err := setup2FA()
		if err != nil {
			printError("%v", err)
			return 1
		}
		v.Enable2FA(secret)
	}
	if err := vault.Save(path, pw1, v); err != nil {
		printError("failed to create vault: %v", err)
		return 1
	}

	printSuccess("vault created at %s", path)
	if *enable2FA {
		printSuccess("two-factor unlock enabled — future unlocks require your master password AND a TOTP code")
	}
	return 0
}

func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	username := fs.String("username", "", "account username")
	url := fs.String("url", "", "associated URL")
	notes := fs.String("notes", "", "free-text notes")
	generate := fs.Bool("generate", false, "generate a random password")
	length := fs.Int("length", 20, "generated password length")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault add [options] <name>")
		return 1
	}
	name := rest[0]

	v, path, masterPw, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	var password string
	if *generate {
		pw, err := vcrypto.GeneratePassword(vcrypto.PasswordOptions{
			Length: *length, Lower: true, Upper: true, Digits: true, Symbols: true,
		})
		if err != nil {
			printError("failed to generate password: %v", err)
			return 1
		}
		password = pw
		printInfo("generated password: %s", password)
	} else {
		pw, err := ReadPassword("Entry password: ")
		if err != nil {
			printError("%v", err)
			return 1
		}
		password = pw
	}

	if _, err := v.Add(name, *username, password, *url, *notes); err != nil {
		printError("%v", err)
		return 1
	}
	if err := vault.Save(path, masterPw, v); err != nil {
		printError("failed to save vault: %v", err)
		return 1
	}

	printSuccess("added entry %q", name)
	return 0
}

func cmdGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	copyFlag := fs.Bool("copy", false, "copy password to clipboard instead of printing it")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault get [-copy] <name>")
		return 1
	}
	name := rest[0]

	v, _, _, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	entry, err := v.Get(name)
	if err != nil {
		printError("%v", err)
		return 1
	}

	if *copyFlag {
		if err := vault.CopyToClipboard(entry.Password); err != nil {
			printError("%v", err)
			return 1
		}
		printClipboardCountdown()
		return 0
	}

	printBold("%s", entry.Name)
	if entry.Username != "" {
		fmt.Printf("  username: %s\n", entry.Username)
	}
	fmt.Printf("  password: %s\n", entry.Password)
	if entry.URL != "" {
		fmt.Printf("  url:      %s\n", entry.URL)
	}
	if entry.Notes != "" {
		fmt.Printf("  notes:    %s\n", entry.Notes)
	}
	return 0
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)

	v, _, _, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	entries := v.List()
	if len(entries) == 0 {
		printWarning("vault is empty")
		return 0
	}
	for _, e := range entries {
		if e.Username != "" {
			fmt.Printf("  %s  (%s)\n", e.Name, e.Username)
		} else {
			fmt.Printf("  %s\n", e.Name)
		}
	}
	return 0
}

func cmdDelete(args []string) int {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault delete <name>")
		return 1
	}
	name := rest[0]

	v, path, masterPw, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	if err := v.Delete(name); err != nil {
		printError("%v", err)
		return 1
	}
	if err := vault.Save(path, masterPw, v); err != nil {
		printError("failed to save vault: %v", err)
		return 1
	}

	printSuccess("deleted entry %q", name)
	return 0
}

func cmdGenerate(args []string) int {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	length := fs.Int("length", 20, "password length")
	noSymbols := fs.Bool("no-symbols", false, "exclude symbols")
	fs.Parse(args)

	pw, err := vcrypto.GeneratePassword(vcrypto.PasswordOptions{
		Length: *length, Lower: true, Upper: true, Digits: true, Symbols: !*noSymbols,
	})
	if err != nil {
		printError("%v", err)
		return 1
	}
	fmt.Println(pw)
	return 0
}

// loadVaultInteractive prompts for the master password and loads the vault
// at the default path, printing an error and returning a nonzero code on
// failure. The returned password is needed by callers that will re-save
// the vault (add/delete).
func loadVaultInteractive() (*vault.Vault, string, string, int) {
	path := DefaultVaultPath()
	if !vault.Exists(path) {
		printError("no vault found at %s — run 'zerovault init' first", path)
		return nil, "", "", 1
	}

	pw, err := ReadPassword("Master password: ")
	if err != nil {
		printError("%v", err)
		return nil, "", "", 1
	}

	v, err := vault.Load(path, pw)
	if err != nil {
		printError("%v", err)
		return nil, "", "", 1
	}

	if v.TwoFAEnabled {
		codeStr, err := ReadLine("TOTP code: ")
		if err != nil {
			printError("%v", err)
			return nil, "", "", 1
		}
		key, err := totp.DecodeSecret(v.TwoFASecret)
		if err != nil {
			printError("%v", err)
			return nil, "", "", 1
		}
		if !totp.Validate(key, codeStr, time.Now(), totp.DefaultPeriod, totp.DefaultDigits, 1) {
			printError("invalid TOTP code")
			return nil, "", "", 1
		}
	}

	return v, path, pw, 0
}
