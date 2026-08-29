package cli

import (
	"flag"
	"io"
	"os"
	"time"

	"zerovault/attacks"
	"zerovault/internal/web"
)

func cmdAttack(args []string) int {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	reportPath := fs.String("report", "", "write a self-contained HTML audit report to this path")
	fs.Parse(args)

	report, err := attacks.RunAll(os.Stdout)
	if err != nil {
		printError("%v", err)
		return 1
	}

	if *reportPath != "" {
		html := attacks.GenerateHTMLReport(report, time.Now())
		if err := os.WriteFile(*reportPath, []byte(html), 0o644); err != nil {
			printError("failed to write report: %v", err)
			return 1
		}
		printSuccess("wrote HTML audit report to %s", *reportPath)
	}

	vulnerable := false
	for _, r := range report.Results {
		if r.Result.Status == attacks.StatusVulnerable {
			vulnerable = true
		}
	}
	if vulnerable {
		return 1
	}
	return 0
}

// attackReportToSnapshot adapts an attacks.Report into the web package's
// AuditSnapshot view type, since internal/web cannot import the attacks
// package directly (attacks imports internal/web for its own test
// harness, so the reverse import would be a cycle).
func attackReportToSnapshot(report attacks.Report, at time.Time) web.AuditSnapshot {
	meta := make(map[string]struct{ Description, Methodology string }, len(attacks.Registry()))
	for _, a := range attacks.Registry() {
		meta[a.Name] = struct{ Description, Methodology string }{a.Description, a.Methodology}
	}

	snap := web.AuditSnapshot{RanAt: at}
	for _, r := range report.Results {
		m := meta[r.Name]
		snap.Results = append(snap.Results, web.AuditResult{
			Category:    r.Category,
			Name:        r.Name,
			Description: m.Description,
			Methodology: m.Methodology,
			Passed:      r.Result.Status != attacks.StatusVulnerable,
			StatusLabel: r.Result.Status.Label(),
			Detail:      r.Result.Detail,
			Duration:    r.Result.Duration.String(),
		})
	}
	return snap
}

// wireAuditRunner connects the web package's audit-page hooks to the
// attacks package's runner and in-memory report cache. Called once, before
// the web server starts handling requests.
func wireAuditRunner() {
	web.AuditRunner = func() (web.AuditSnapshot, error) {
		report, err := attacks.RunAll(io.Discard)
		if err != nil {
			return web.AuditSnapshot{}, err
		}
		return attackReportToSnapshot(report, time.Now()), nil
	}
	web.AuditLastResult = func() (web.AuditSnapshot, bool) {
		report, at, ok := attacks.LastReport()
		if !ok {
			return web.AuditSnapshot{}, false
		}
		return attackReportToSnapshot(report, at), true
	}
}
