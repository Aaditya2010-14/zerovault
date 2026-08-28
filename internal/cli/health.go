package cli

import (
	"flag"
	"fmt"
	"time"

	"zerovault/internal/health"
)

// cmdHealth implements `zerovault health`: prints the same analysis the
// dashboard's /health page shows, colorized for the terminal.
func cmdHealth(args []string) int {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	fs.Parse(args)

	v, _, _, code := loadVaultInteractive()
	if code != 0 {
		return code
	}

	r := health.Analyze(v, time.Now())

	scoreColor := colorGreen
	if r.Score < 50 {
		scoreColor = colorRed
	} else if r.Score < 80 {
		scoreColor = colorYellow
	}
	fmt.Println()
	printBold("VAULT HEALTH SCORE")
	fmt.Printf(scoreColor+"  %d%%"+colorReset+"\n\n", r.Score)

	if len(r.Critical) > 0 {
		fmt.Printf(colorRed+"CRITICAL (%d)"+colorReset+"\n", len(r.Critical))
		for _, issue := range r.Critical {
			fmt.Printf("  ⚠ %s\n", issue.Message)
		}
		fmt.Println()
	}
	if len(r.Warning) > 0 {
		fmt.Printf(colorYellow+"WARNING (%d)"+colorReset+"\n", len(r.Warning))
		for _, issue := range r.Warning {
			fmt.Printf("  ⚠ %s\n", issue.Message)
		}
		fmt.Println()
	}

	var strong []health.EntryHealth
	for _, e := range r.Entries {
		if e.Strength >= health.Strong {
			strong = append(strong, e)
		}
	}
	if len(strong) > 0 {
		fmt.Printf(colorGreen+"STRONG (%d)"+colorReset+"\n", len(strong))
		for _, e := range strong {
			fmt.Printf("  ✓ %s: %s (%.0f bits)\n", e.Name, e.Strength, e.Bits)
		}
	}

	if len(r.Entries) == 0 {
		printWarning("vault is empty — nothing to analyze")
	}
	return 0
}
