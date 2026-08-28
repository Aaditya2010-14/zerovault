package cli

import (
	"flag"
	"fmt"
	"time"

	"zerovault/internal/totp"
	"zerovault/internal/vault"
)

// cmdTOTP dispatches "zerovault totp <subcommand>".
func cmdTOTP(args []string) int {
	if len(args) == 0 {
		printError("usage: zerovault totp <add|get|list> ...")
		return 1
	}

	switch args[0] {
	case "add":
		return cmdTOTPAdd(args[1:])
	case "get":
		return cmdTOTPGet(args[1:])
	case "list":
		return cmdTOTPList(args[1:])
	default:
		printError("unknown totp subcommand %q", args[0])
		return 1
	}
}

func cmdTOTPAdd(args []string) int {
	fs := flag.NewFlagSet("totp add", flag.ExitOnError)
	digits := fs.Int("digits", totp.DefaultDigits, "code length")
	period := fs.Int("period", totp.DefaultPeriod, "time step in seconds")
	generate := fs.Bool("generate", false, "generate a new random secret instead of prompting for one")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault totp add [options] <name>")
		return 1
	}
	name := rest[0]

	v, path, masterPw, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	var secret string
	if *generate {
		s, err := totp.GenerateSecret()
		if err != nil {
			printError("%v", err)
			return 1
		}
		secret = s
		printInfo("generated secret: %s", secret)
	} else {
		pw, err := ReadPassword("TOTP secret (base32, from the site's QR/setup screen): ")
		if err != nil {
			printError("%v", err)
			return 1
		}
		secret = pw
	}

	if _, err := v.AddTOTP(name, secret, *digits, *period); err != nil {
		printError("%v", err)
		return 1
	}
	if err := vault.Save(path, masterPw, v); err != nil {
		printError("failed to save vault: %v", err)
		return 1
	}

	printSuccess("added TOTP entry %q", name)
	return 0
}

func cmdTOTPGet(args []string) int {
	fs := flag.NewFlagSet("totp get", flag.ExitOnError)
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault totp get <name>")
		return 1
	}
	name := rest[0]

	v, _, _, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	entry, err := v.GetTOTP(name)
	if err != nil {
		printError("%v", err)
		return 1
	}

	totpCode, err := entry.CurrentCode()
	if err != nil {
		printError("%v", err)
		return 1
	}

	fmt.Printf("%s: %s (refreshes in %ds)\n", entry.Name, totpCode, totp.RemainingSeconds(time.Now()))
	return 0
}

func cmdTOTPList(args []string) int {
	fs := flag.NewFlagSet("totp list", flag.ExitOnError)
	fs.Parse(args)

	v, _, _, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	entries := v.ListTOTP()
	if len(entries) == 0 {
		printWarning("no TOTP entries")
		return 0
	}
	for _, e := range entries {
		totpCode, err := e.CurrentCode()
		if err != nil {
			printError("%s: %v", e.Name, err)
			continue
		}
		fmt.Printf("  %-20s %s\n", e.Name, totpCode)
	}
	return 0
}
