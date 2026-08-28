package cli

import (
	"flag"
	"fmt"

	"zerovault/internal/scanner"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	minEntropy := fs.Float64("min-entropy", scanner.MinEntropy, "entropy threshold for generic secret detection")
	fs.Parse(args)

	rest := fs.Args()
	path := "."
	if len(rest) == 1 {
		path = rest[0]
	} else if len(rest) > 1 {
		printError("usage: zerovault scan [options] <path>")
		return 1
	}

	printInfo("scanning %s ...", path)
	findings, err := scanner.ScanDir(path, scanner.Options{MinEntropy: *minEntropy})
	if err != nil {
		printError("%v", err)
		return 1
	}

	if len(findings) == 0 {
		printSuccess("no secrets found")
		return 0
	}

	critical, warnings := 0, 0
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical {
			fmt.Printf(colorRed+"[CRITICAL]"+colorReset+" %s:%d  %s  %s\n", f.File, f.Line, f.Pattern, f.Match)
			critical++
		} else {
			fmt.Printf(colorYellow+"[WARNING] "+colorReset+" %s:%d  %s  %s\n", f.File, f.Line, f.Pattern, f.Match)
			warnings++
		}
	}

	fmt.Println()
	printBold("%d finding(s): %d critical, %d warning", len(findings), critical, warnings)

	if critical > 0 {
		return 2
	}
	return 1
}
