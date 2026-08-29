// Package cli implements ZeroVault's command-line interface: argument
// parsing, command dispatch, and ANSI-colored terminal output.
package cli

import (
	"fmt"
	"time"

	"zerovault/internal/vault"
)

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

// printClipboardCountdown blocks in the foreground for
// vault.ClipboardClearDelay, printing a live "clears in Ns..." countdown,
// then clears the clipboard itself. The clear runs synchronously in this
// same goroutine (not a fire-and-forget background one) so the process
// never exits before the clipboard is actually wiped.
func printClipboardCountdown() {
	total := int(vault.ClipboardClearDelay / time.Second)
	fmt.Printf(colorGreen + "✓ Password copied. Clipboard clears in " + colorReset)
	for remaining := total; remaining > 0; remaining-- {
		fmt.Printf(colorGreen+"%ds... "+colorReset, remaining)
		time.Sleep(time.Second)
	}
	if err := vault.ClearClipboard(); err != nil {
		fmt.Print("\r" + colorRed + "✗ failed to clear clipboard: " + err.Error() + "                    " + colorReset + "\n")
		return
	}
	fmt.Print("\r" + colorGreen + "✓ Clipboard cleared.                              " + colorReset + "\n")
}
