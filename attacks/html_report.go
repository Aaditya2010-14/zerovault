package attacks

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// GenerateHTMLReport renders a self-contained security audit report as a
// single HTML document (inline CSS, no external assets, no JavaScript) so
// it can be opened directly from disk or emailed as an attachment.
func GenerateHTMLReport(report Report, generatedAt time.Time) string {
	total := len(report.Results)
	passed := 0
	failed := 0
	for _, r := range report.Results {
		if r.Result.Status == StatusVulnerable {
			failed++
		} else {
			passed++
		}
	}

	verdict := "SECURE"
	verdictClass := "pass"
	if failed > 0 {
		verdict = "VULNERABILITIES FOUND"
		verdictClass = "fail"
	}

	var rows strings.Builder
	lastCategory := ""
	for _, r := range report.Results {
		if r.Category != lastCategory {
			fmt.Fprintf(&rows, "<tr class=\"category-row\"><td colspan=\"5\">%s</td></tr>\n", html.EscapeString(r.Category))
			lastCategory = r.Category
		}
		desc, method := descriptionFor(report, r.Name)
		badgeClass, badgeLabel := badgeFor(r.Result.Status)
		fmt.Fprintf(&rows, `<tr>
  <td><strong>%s</strong><div class="desc">%s</div><div class="method">%s</div></td>
  <td>%s</td>
  <td><span class="badge badge-%s">%s</span></td>
  <td>%s</td>
  <td>%s</td>
</tr>
`,
			html.EscapeString(r.Name),
			html.EscapeString(desc),
			html.EscapeString(method),
			html.EscapeString(r.Category),
			badgeClass, badgeLabel,
			html.EscapeString(r.Result.Detail),
			html.EscapeString(formatDuration(r.Result.Duration)),
		)
	}

	return fmt.Sprintf(htmlReportTemplate,
		html.EscapeString(Version),
		generatedAt.Format("2006-01-02 15:04:05 MST"),
		html.EscapeString(Version),
		total, passed, failed,
		verdictClass, html.EscapeString(verdict),
		rows.String(),
		formatDuration(report.Total),
	)
}

// descriptionFor looks up the registry entry matching a result's name so
// the report can show the same Description/Methodology text the /audit
// web page uses, without threading it through Report itself.
func descriptionFor(_ Report, name string) (description, methodology string) {
	for _, a := range registry {
		if a.Name == name {
			return a.Description, a.Methodology
		}
	}
	return "", ""
}

func badgeFor(s Status) (class, label string) {
	switch s {
	case StatusVulnerable:
		return "fail", "FAIL"
	default:
		return "pass", "PASS"
	}
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZeroVault Security Audit Report</title>
<style>
  :root {
    --bg: #f7f8fa;
    --card: #ffffff;
    --border: #e2e5ea;
    --text: #1c1f26;
    --text-dim: #5b6270;
    --accent: #2f6fed;
    --green: #1a9e5c;
    --green-bg: #e7f7ef;
    --red: #d0342c;
    --red-bg: #fdeceb;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }
  header {
    background: linear-gradient(135deg, #1c2333, #2a3550);
    color: #fff;
    padding: 2.5rem 2rem;
  }
  header h1 { margin: 0 0 0.25rem; font-size: 1.6rem; }
  header .meta { color: #b7c0d6; font-size: 0.9rem; }
  main { max-width: 980px; margin: 0 auto; padding: 2rem; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    text-align: center;
  }
  .summary-grid .stat { padding: 0.5rem; }
  .summary-grid .stat .n { font-size: 1.8rem; font-weight: 700; }
  .summary-grid .stat .label { color: var(--text-dim); font-size: 0.85rem; }
  .verdict-pass { color: var(--green); }
  .verdict-fail { color: var(--red); }
  table { width: 100%%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.65rem 0.6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--text-dim); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }
  tr.category-row td { background: #eef1f6; font-weight: 700; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); padding: 0.4rem 0.6rem; }
  .desc { color: var(--text-dim); font-weight: 400; font-size: 0.85rem; margin-top: 0.2rem; }
  .method { color: #8890a0; font-weight: 400; font-size: 0.78rem; margin-top: 0.15rem; font-style: italic; }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.78rem; font-weight: 700; }
  .badge-pass { background: var(--green-bg); color: var(--green); }
  .badge-fail { background: var(--red-bg); color: var(--red); }
  footer { text-align: center; color: var(--text-dim); font-size: 0.85rem; padding: 2rem 1rem 3rem; }
</style>
</head>
<body>
<header>
  <h1>ZeroVault Security Audit Report</h1>
  <div class="meta">Generated %s &middot; Report generated %s &middot; ZeroVault v%s</div>
</header>
<main>
  <div class="card">
    <div class="summary-grid">
      <div class="stat"><div class="n">%d</div><div class="label">Total Tests</div></div>
      <div class="stat"><div class="n" style="color:var(--green);">%d</div><div class="label">Passed</div></div>
      <div class="stat"><div class="n" style="color:var(--red);">%d</div><div class="label">Failed</div></div>
      <div class="stat"><div class="n verdict-%s">%s</div><div class="label">Verdict</div></div>
    </div>
  </div>

  <div class="card">
    <table>
      <thead>
        <tr><th>Test</th><th>Category</th><th>Result</th><th>Detail</th><th>Duration</th></tr>
      </thead>
      <tbody>
%s
      </tbody>
    </table>
  </div>

  <div class="card" style="text-align:center; color: var(--text-dim);">
    Total run time: %s
  </div>

  <footer>
    All cryptographic operations use Go 1.27 standard library. Zero third-party dependencies.
  </footer>
</main>
</body>
</html>
`
