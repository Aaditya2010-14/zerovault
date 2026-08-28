package cli

import (
	"flag"

	"zerovault/internal/vault"
)

// cmdRekey implements `zerovault rekey`: re-encrypts the vault under a new
// master password. See vault.Rekey for the atomic-write / verify-on-new-
// password guarantees.
func cmdRekey(args []string) int {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	fs.Parse(args)

	path := DefaultVaultPath()
	if !vault.Exists(path) {
		printError("no vault found at %s — run 'zerovault init' first", path)
		return 1
	}

	currentPw, err := ReadPassword("Current master password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}

	newPw1, err := ReadPassword("New master password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	newPw2, err := ReadPassword("Confirm new master password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	if newPw1 != newPw2 {
		printError("new passwords do not match")
		return 1
	}
	if newPw1 == "" {
		printError("new password cannot be empty")
		return 1
	}
	if newPw1 == currentPw {
		printWarning("new password is the same as the current one")
	}

	v, err := vault.Rekey(path, currentPw, newPw1)
	if err != nil {
		printError("%v", err)
		return 1
	}

	printSuccess("vault re-encrypted with new master password. %d entries secured.", len(v.Entries)+len(v.TOTPEntries))
	return 0
}
