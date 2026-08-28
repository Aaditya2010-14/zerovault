package cli

import (
	"flag"
	"fmt"
	"time"

	"zerovault/internal/gitscan"
	"zerovault/internal/scanner"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	minEntropy := fs.Float64("min-entropy", scanner.MinEntropy, "entropy threshold for generic secret detection")
	gitPath := fs.String("git", "", "scan git commit history at this repo path instead of the working tree")
	depth := fs.Int("depth", 50, "max commits to scan from HEAD (git mode only)")
	fs.Parse(args)

	if *gitPath != "" {
		return cmdScanGit(*gitPath, *depth, *minEntropy)
	}

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

// cmdScanGit implements `zerovault scan --git <repo-path> [--depth N]`:
// walks the repository's commit history by reading .git/objects directly
// (internal/gitscan) and scans every historical file blob it finds, not
// just what's currently checked out.
func cmdScanGit(repoPath string, depth int, minEntropy float64) int {
	printInfo("scanning git history (last %d commits) at %s ...", depth, repoPath)

	report, err := gitscan.ScanRepo(repoPath, depth, minEntropy)
	if err != nil {
		printError("%v", err)
		return 1
	}
	fmt.Println()

	if len(report.Findings) == 0 {
		printSuccess("no secrets found in %d commits, %d file versions", report.CommitsScanned, report.BlobsScanned)
		return 0
	}

	critical, warnings := 0, 0
	for _, f := range report.Findings {
		label := colorYellow + "HIGH    " + colorReset
		if f.Severity == "critical" {
			label = colorRed + "CRITICAL" + colorReset
			critical++
		} else {
			warnings++
		}

		fmt.Printf("%s  commit %s (%s) by %s\n", label, f.CommitSHA[:7], f.Date.Format("2006-01-02"), f.Author)
		fileNote := f.Path
		if f.DeletedLater {
			fileNote += "  (deleted in a later commit — but still in history!)"
		}
		fmt.Printf("          file: %s\n", fileNote)
		fmt.Printf("          %s: %s\n\n", f.Pattern, f.Match)
	}

	fmt.Printf("Scanned: %d commits, %d file versions | Found: %d secret(s) | Time: %s\n",
		report.CommitsScanned, report.BlobsScanned, len(report.Findings), formatDuration(report.Elapsed))
	if report.Truncated {
		printWarning("history has more commits than the --depth limit (%d) — increase it to scan further back", depth)
	}
	fmt.Println()
	printWarning("These secrets exist in git history even if the files were deleted.")
	printWarning("Run 'git filter-branch' or 'git-filter-repo' to remove them permanently.")

	if critical > 0 {
		return 2
	}
	if warnings > 0 {
		return 1
	}
	return 0
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
