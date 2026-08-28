// Package cli implements ZeroVault's command-line interface: argument
// parsing, command dispatch, and ANSI-colored terminal output.
package cli

import "fmt"

// ANSI color codes for terminal output. Kept minimal and stdlib-only —
// no third-party terminal color library.
const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	colorBold   = "\x1b[1m"
)

func printSuccess(format string, args ...any) {
	fmt.Printf(colorGreen+"✓ "+format+colorReset+"\n", args...)
}

func printError(format string, args ...any) {
	fmt.Printf(colorRed+"✗ "+format+colorReset+"\n", args...)
}

func printInfo(format string, args ...any) {
	fmt.Printf(colorCyan+format+colorReset+"\n", args...)
}

func printWarning(format string, args ...any) {
	fmt.Printf(colorYellow+"⚠ "+format+colorReset+"\n", args...)
}

func printBold(format string, args ...any) {
	fmt.Printf(colorBold+format+colorReset+"\n", args...)
}
