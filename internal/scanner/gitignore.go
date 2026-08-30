package scanner

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// gitignoreRule is one parsed line from a .gitignore file.
type gitignoreRule struct {
	baseDir  string // slash-separated dir (relative to the scan root) the .gitignore lives in; "" for the root
	pattern  string // pattern text, with any leading "!" and trailing "/" already stripped
	negate   bool   // "!pattern" — re-includes a path an earlier rule ignored
	dirOnly  bool   // pattern ended in "/" — only matches directories
	anchored bool   // pattern contained a "/" other than a single trailing one — matched against the
	// full path relative to baseDir, not just the basename
}

// GitignoreMatcher answers "is this path ignored?" against every .gitignore
// found under a root directory, including nested ones in subdirectories.
// Rules are kept in discovery order (root .gitignore before nested ones,
// and within one file, top to bottom) so matches() can apply git's own
// "last matching rule wins" precedence — including negation — by scanning
// the whole rule list in that order.
type GitignoreMatcher struct {
	rules []gitignoreRule
}

// LoadGitignoreMatcher walks root looking for .gitignore files — the root's
// own and any in subdirectories — and returns a matcher built from all of
// them. A root with no .gitignore anywhere returns a matcher that ignores
// nothing (never nil), so callers don't need a separate "no gitignore"
// branch.
func LoadGitignoreMatcher(root string) (*GitignoreMatcher, error) {
	m := &GitignoreMatcher{}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree — skip it, don't abort the whole scan
		}
		if d.IsDir() {
			// .gitignore rules never come from inside .git itself, and
			// walking into it just to check is wasted work.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != ".gitignore" {
			return nil
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		baseDir, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			baseDir = ""
		}
		if baseDir == "." {
			baseDir = ""
		}
		m.rules = append(m.rules, parseGitignore(filepath.ToSlash(baseDir), string(content))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// parseGitignore turns one .gitignore file's content into rules scoped to
// baseDir, per the documented .gitignore format: blank lines and lines
// starting with "#" are skipped, "!" negates, a trailing "/" restricts the
// pattern to directories, and any other "/" in the pattern anchors it to
// baseDir instead of letting it match at any depth beneath it.
func parseGitignore(baseDir, content string) []gitignoreRule {
	var rules []gitignoreRule
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		negate := false
		if strings.HasPrefix(trimmed, "!") {
			negate = true
			trimmed = trimmed[1:]
		}

		dirOnly := false
		if strings.HasSuffix(trimmed, "/") {
			dirOnly = true
			trimmed = strings.TrimSuffix(trimmed, "/")
		}
		if trimmed == "" {
			continue
		}

		leadingSlash := strings.HasPrefix(trimmed, "/")
		trimmed = strings.TrimPrefix(trimmed, "/")
		if trimmed == "" {
			continue
		}
		anchored := leadingSlash || strings.Contains(trimmed, "/")

		rules = append(rules, gitignoreRule{
			baseDir:  baseDir,
			pattern:  trimmed,
			negate:   negate,
			dirOnly:  dirOnly,
			anchored: anchored,
		})
	}
	return rules
}

// Matches reports whether relPath (slash-separated, relative to the scan
// root LoadGitignoreMatcher was called with) is ignored. isDir must reflect
// whether relPath is a directory, since a "foo/"-style rule only ever
// matches directories.
func (m *GitignoreMatcher) Matches(relPath string, isDir bool) bool {
	relPath = filepath.ToSlash(relPath)
	ignored := false
	for _, r := range m.rules {
		if !r.applies(relPath) {
			continue
		}
		if r.dirOnly && !isDir {
			continue
		}
		if r.match(relPath) {
			ignored = !r.negate
		}
	}
	return ignored
}

// applies reports whether relPath falls under the directory the rule's
// .gitignore was found in — a nested .gitignore's rules never reach outside
// its own subtree.
func (r gitignoreRule) applies(relPath string) bool {
	if r.baseDir == "" {
		return true
	}
	return relPath == r.baseDir || strings.HasPrefix(relPath, r.baseDir+"/")
}

// match tests the rule's pattern against relPath: an anchored pattern
// (one that contains a "/") is matched against the whole path relative to
// baseDir, while an unanchored one (a bare filename or "*.ext") is matched
// against just the final path segment, so it matches at any depth — e.g.
// "secrets.env" ignores that filename anywhere under baseDir, not only
// directly inside it.
func (r gitignoreRule) match(relPath string) bool {
	target := relPath
	if r.baseDir != "" {
		target = strings.TrimPrefix(relPath, r.baseDir+"/")
	}
	if r.anchored {
		ok, err := path.Match(r.pattern, target)
		return err == nil && ok
	}
	ok, err := path.Match(r.pattern, path.Base(target))
	return err == nil && ok
}
