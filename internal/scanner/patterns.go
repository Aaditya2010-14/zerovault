// Package scanner walks a directory tree looking for leaked secrets: known
// API key/token formats (via regexp) and generic high-entropy string
// literals assigned to suspiciously named variables (via Shannon entropy).
package scanner

import "regexp"

// Severity classifies how confident a match is at being a real secret.
type Severity string

const (
	SeverityCritical Severity = "critical" // known, high-confidence secret format
	SeverityWarning  Severity = "warning"  // plausible but generic (e.g. entropy-based)
)

// Pattern is a named regex used to detect a specific kind of leaked secret.
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity Severity
}

// Patterns is the list of known secret formats the scanner checks every
// line against. Regexes are deliberately anchored to well-documented,
// stable prefixes (AWS "AKIA", GitHub "ghp_", etc.) to keep the false
// positive rate low.
var Patterns = []Pattern{
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "AWS Secret Access Key",
		Regex:    regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Severity: SeverityCritical,
	},
	{
		Name:     "GitHub Personal Access Token",
		Regex:    regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "GitHub OAuth Token",
		Regex:    regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "GitHub Fine-Grained PAT",
		Regex:    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Slack Webhook URL",
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Stripe Live Secret Key",
		Regex:    regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Stripe Live Publishable Key",
		Regex:    regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: SeverityWarning,
	},
	{
		Name:     "Twilio API Key",
		Regex:    regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "SendGrid API Key",
		Regex:    regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "npm Access Token",
		Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		Severity: SeverityCritical,
	},
	{
		Name:     "PGP/RSA/EC Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----`),
		Severity: SeverityCritical,
	},
	{
		Name:     "JSON Web Token",
		Regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		Severity: SeverityWarning,
	},
	{
		Name:     "Credentials in URL",
		Regex:    regexp.MustCompile(`\w+://[^\s:@/]+:[^\s:@/]+@[^\s/]+`),
		Severity: SeverityWarning,
	},
	{
		Name:     "Generic API Key Assignment",
		Regex:    regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,64}['"]`),
		Severity: SeverityWarning,
	},
	{
		Name:     "Generic Secret Assignment",
		Regex:    regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{8,64}['"]`),
		Severity: SeverityWarning,
	},
}

// assignmentPattern extracts a quoted string literal assigned to a
// suspiciously-named identifier, used for entropy-based detection of
// secrets that don't match any known format above.
var assignmentPattern = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|pwd|credential)\w*\s*[:=]\s*['"]([A-Za-z0-9+/=_\-.]{12,})['"]`)
