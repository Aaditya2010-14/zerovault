package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Finding is a single potential secret detected in a file.
type Finding struct {
	File     string
	Line     int
	Pattern  string
	Severity Severity
	Match    string // redacted match text, safe to print
}

// Options controls scan behavior.
type Options struct {
	MinEntropy  float64 // entropy threshold for generic secret detection; 0 uses MinEntropy
	SkipDirs    []string
	MaxFileSize int64 // files larger than this are skipped; 0 uses defaultMaxFileSize
}

const defaultMaxFileSize = 5 * 1024 * 1024 // 5MB — secrets don't hide in multi-megabyte files

// defaultSkipDirs are directories that are never worth scanning: VCS
// metadata, dependency trees, and build output. Skipping them keeps the
// scan fast and avoids false positives inside vendored third-party code.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".zerovault":   true,
	"dist":         true,
	"build":        true,
	".venv":        true,
	"__pycache__":  true,
}

// binaryExtensions are file extensions never worth scanning as text.
var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".webp": true,
	".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true,
	".pdf": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true,
}

// ScanDir walks root recursively and returns every Finding across all
// scannable files, sorted by file then line for stable, readable output.
func ScanDir(root string, opts Options) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("scanner: directory not found: %s", root)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scanner: not a directory: %s", root)
	}

	skipDirs := defaultSkipDirs
	if len(opts.SkipDirs) > 0 {
		skipDirs = make(map[string]bool, len(defaultSkipDirs)+len(opts.SkipDirs))
		for k := range defaultSkipDirs {
			skipDirs[k] = true
		}
		for _, d := range opts.SkipDirs {
			skipDirs[d] = true
		}
	}
	maxSize := opts.MaxFileSize
	if maxSize == 0 {
		maxSize = defaultMaxFileSize
	}
	minEntropy := opts.MinEntropy
	if minEntropy == 0 {
		minEntropy = MinEntropy
	}

	// A gitignored file won't be in the repo, so it shouldn't be scanned or
	// flagged. LoadGitignoreMatcher never fails the whole scan on error —
	// a repo with an unreadable .gitignore just gets treated as having none.
	gim, _ := LoadGitignoreMatcher(root)

	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relPath = path
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if relPath != "." && gim.Matches(relPath, true) {
				return filepath.SkipDir
			}
			return nil
		}
		if gim.Matches(relPath, false) {
			return nil
		}
		if binaryExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil // unreadable file metadata — skip, don't abort the whole scan
		}
		if info.Size() > maxSize || info.Size() == 0 {
			return nil
		}

		fileFindings, err := ScanFile(path, minEntropy)
		if err != nil {
			return nil // unreadable/binary file — skip, don't abort the whole scan
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanner: failed to walk %s: %w", root, err)
	}
	return findings, nil
}

// ScanFile scans a single file for known secret patterns and high-entropy
// generic assignments, line by line.
func ScanFile(path string, minEntropy float64) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner: failed to open %s: %w", path, err)
	}
	defer f.Close()

	if isBinary(f) {
		return nil, nil
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("scanner: failed to rewind %s: %w", path, err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // tolerate long lines (minified JS etc.)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		var lineFindings []Finding
		hasCritical := false
		for _, p := range Patterns {
			if loc := p.Regex.FindStringIndex(line); loc != nil {
				lineFindings = append(lineFindings, Finding{
					File:     path,
					Line:     lineNum,
					Pattern:  p.Name,
					Severity: p.Severity,
					Match:    redact(line[loc[0]:loc[1]]),
				})
				if p.Severity == SeverityCritical {
					hasCritical = true
				}
			}
		}

		// A critical, specific-format match (AWS key, GitHub token, ...)
		// makes the generic catch-all patterns on the same line redundant
		// noise reporting the same secret twice under a vaguer name.
		if hasCritical {
			kept := lineFindings[:0]
			for _, f := range lineFindings {
				if f.Pattern == "Generic API Key Assignment" || f.Pattern == "Generic Secret Assignment" {
					continue
				}
				kept = append(kept, f)
			}
			lineFindings = kept
		}
		findings = append(findings, lineFindings...)
		matchedNamed := len(lineFindings) > 0

		// Only run entropy-based detection when no named pattern already
		// matched this line, to avoid double-reporting the same secret.
		if !matchedNamed {
			if m := assignmentPattern.FindStringSubmatch(line); m != nil {
				value := m[2]
				if entropy := ShannonEntropy(value); entropy >= minEntropy {
					findings = append(findings, Finding{
						File:     path,
						Line:     lineNum,
						Pattern:  fmt.Sprintf("High-Entropy Secret Assignment (entropy %.1f)", entropy),
						Severity: SeverityWarning,
						Match:    redact(value),
					})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: error reading %s: %w", path, err)
	}

	return findings, nil
}

// ScanBytes runs the same pattern + entropy detection ScanFile applies to
// a file on disk, but against an in-memory byte slice. This is what the
// git history scanner (internal/gitscan) uses to scan blob content pulled
// straight out of .git/objects — there's no file on disk to open, since
// the content only exists inside a historical commit.
func ScanBytes(name string, data []byte, minEntropy float64) []Finding {
	if isBinaryData(data) {
		return nil
	}

	var findings []Finding
	lineScanner := bufio.NewScanner(bytes.NewReader(data))
	lineScanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNum := 0
	for lineScanner.Scan() {
		lineNum++
		line := lineScanner.Text()

		var lineFindings []Finding
		hasCritical := false
		for _, p := range Patterns {
			if loc := p.Regex.FindStringIndex(line); loc != nil {
				lineFindings = append(lineFindings, Finding{
					File:     name,
					Line:     lineNum,
					Pattern:  p.Name,
					Severity: p.Severity,
					Match:    redact(line[loc[0]:loc[1]]),
				})
				if p.Severity == SeverityCritical {
					hasCritical = true
				}
			}
		}
		if hasCritical {
			kept := lineFindings[:0]
			for _, f := range lineFindings {
				if f.Pattern == "Generic API Key Assignment" || f.Pattern == "Generic Secret Assignment" {
					continue
				}
				kept = append(kept, f)
			}
			lineFindings = kept
		}
		findings = append(findings, lineFindings...)

		if len(lineFindings) == 0 {
			if m := assignmentPattern.FindStringSubmatch(line); m != nil {
				value := m[2]
				if entropy := ShannonEntropy(value); entropy >= minEntropy {
					findings = append(findings, Finding{
						File:     name,
						Line:     lineNum,
						Pattern:  fmt.Sprintf("High-Entropy Secret Assignment (entropy %.1f)", entropy),
						Severity: SeverityWarning,
						Match:    redact(value),
					})
				}
			}
		}
	}
	return findings
}

func isBinaryData(data []byte) bool {
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	return bytes.IndexByte(data[:n], 0) != -1
}

// isBinary sniffs the first 8KB of f for a NUL byte, the standard
// heuristic for distinguishing text from binary content.
func isBinary(f *os.File) bool {
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) != -1
}

// redact shortens a matched secret to its first and last 4 characters so
// scan output never itself leaks the full secret to a terminal, log file,
// or screen-share.
func redact(s string) string {
	if len(s) <= 10 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-4:]
}
