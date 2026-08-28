// Command zerovault is the entry point for the ZeroVault CLI and web
// dashboard: an encrypted password manager, TOTP generator, and secrets
// scanner built entirely on the Go standard library.
package main

import (
	"os"

	"zerovault/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
