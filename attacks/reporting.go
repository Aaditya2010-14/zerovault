package attacks

import (
	"fmt"
	"io"
)

// --- REPORTING ---
//
// Everything below is presentation only: it reads the results the attack
// logic already produced and formats them for the terminal. No attack, no
// crypto, no HTTP happens in this file.

func printBanner(w io.Writer, n int) {
	fmt.Fprintln(w, "╔══════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║                 ZEROVAULT SECURITY AUDIT                     ║")
	fmt.Fprintln(w, "║              Automated Penetration Test Suite                ║")
	fmt.Fprintln(w, "╚══════════════════════════════════════════════════════════════╝")
	fmt.Fprintf(w, "\nRunning %d security tests against a disposable fixture vault...\n", n)
}

func printScorecard(w io.Writer, r Report) {
	blocked, secure, expected, vulnerable := 0, 0, 0, 0
	for _, nr := range r.Results {
		switch nr.Result.Status {
		case StatusBlocked:
			blocked++
		case StatusSecure:
			secure++
		case StatusExpected:
			expected++
		default:
			vulnerable++
		}
	}

	fmt.Fprintln(w, "\n══════════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "RESULTS: %d blocked | %d secure | %d expected | %d vulnerabilities found\n",
		blocked, secure, expected, vulnerable)
	fmt.Fprintf(w, "TOTAL TIME: %s\n", formatDuration(r.Total))

	if vulnerable > 0 {
		fmt.Fprintln(w, "\n✗ ZeroVault FAILED one or more security tests. See details above.")
		for _, nr := range r.Results {
			if nr.Result.Status == StatusVulnerable {
				fmt.Fprintf(w, "  - %s: %s\n", nr.Name, nr.Result.Detail)
			}
		}
	} else {
		fmt.Fprintln(w, "\nZeroVault passed all security tests.")
		fmt.Fprintln(w, "All crypto primitives from Go 1.27 standard library.")
		fmt.Fprintln(w, "Zero third-party dependencies.")
	}
	fmt.Fprintln(w, "══════════════════════════════════════════════════════════════")
}
