// Package gitscan scans a git repository's commit history for leaked
// secrets by reading the objects under .git/objects directly — no
// shelling out to the `git` binary. Git's object database is a simple,
// well-documented format: each object is zlib-compressed
// ("<type> <size>\0<content>"), addressed by the SHA-1 of that content,
// and commits/trees/blobs form a Merkle DAG walked by following SHA
// references. Reimplementing that walk from scratch is what lets
// `zerovault scan --git` find secrets even in commits whose files were
// later deleted — something a plain directory scan can never see, because
// it only looks at the current working tree.
//
// Only loose objects (.git/objects/xx/yyyy...) are read; a repository
// that has been `git gc`'d into packfiles is out of scope (see README's
// threat model / edge cases) — small, actively-developed repos (exactly
// the kind this feature targets) stay loose until thousands of objects
// accumulate.
package gitscan

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"zerovault/internal/scanner"
)

// Commit is a parsed commit object.
type Commit struct {
	SHA     string
	Tree    string
	Parents []string
	Author  string
	Email   string
	Date    time.Time
	Message string
}

// TreeEntry is one entry (file or subdirectory) inside a tree object.
type TreeEntry struct {
	Mode string
	Name string
	SHA  string
}

// Finding is one secret found in historical git content.
type Finding struct {
	CommitSHA    string
	Author       string
	Date         time.Time
	Path         string
	Pattern      string
	Severity     scanner.Severity
	Match        string
	DeletedLater bool // this path no longer exists in HEAD's tree
}

// Report is the result of scanning a repository's history.
type Report struct {
	CommitsScanned int
	BlobsScanned   int
	Findings       []Finding
	Elapsed        time.Duration
	Truncated      bool // hit the depth limit before exhausting history
}

// ErrNotAGitRepo is returned when path has no .git directory.
var ErrNotAGitRepo = fmt.Errorf("gitscan: not a git repository (no .git directory found)")

// repo bundles the on-disk location and a small object cache so the same
// blob (identical content, hence identical SHA, appearing in many commits)
// is only ever decompressed and scanned once.
type repo struct {
	gitDir       string
	objectCache  map[string][]byte // sha -> decompressed content
	objectType   map[string]string
	scannedBlobs map[string]bool // blob SHAs already scanned for secrets
}

// ScanRepo walks up to maxCommits commits of history starting at HEAD,
// scanning every distinct file blob it encounters for leaked secrets with
// the same pattern + entropy detection the regular directory scanner uses.
func ScanRepo(repoPath string, maxCommits int, minEntropy float64) (Report, error) {
	start := time.Now()

	gitDir := filepath.Join(repoPath, ".git")
	if info, err := os.Stat(gitDir); err != nil || !info.IsDir() {
		return Report{}, ErrNotAGitRepo
	}

	r := &repo{
		gitDir:       gitDir,
		objectCache:  make(map[string][]byte),
		objectType:   make(map[string]string),
		scannedBlobs: make(map[string]bool),
	}

	head, err := resolveHEAD(gitDir)
	if err != nil {
		return Report{}, err
	}

	commits, truncated, err := walkCommits(r, head, maxCommits)
	if err != nil {
		return Report{}, err
	}

	// HEAD's own tree defines "currently present" for the
	// deleted-but-still-in-history flag.
	headPaths := map[string]bool{}
	if len(commits) > 0 {
		entries, err := flattenTree(r, commits[0].Tree, "")
		if err == nil {
			for _, e := range entries {
				headPaths[e.path] = true
			}
		}
	}

	// The live, on-disk .gitignore governs the working tree, so a path
	// that's currently gitignored should be filtered out of findings even
	// though it's a real historical blob — it's the "working-tree mode"
	// counterpart to the file scanner's gitignore skip. Paths that are gone
	// from HEAD entirely (headPaths[path] == false) are exactly the
	// deleted-secret case this scanner exists to catch, so they're left
	// alone regardless of the current .gitignore.
	gim, _ := scanner.LoadGitignoreMatcher(repoPath)

	report := Report{CommitsScanned: len(commits), Truncated: truncated}
	for _, c := range commits {
		entries, err := flattenTree(r, c.Tree, "")
		if err != nil {
			continue // a corrupt/missing subtree shouldn't abort the whole scan
		}
		for _, e := range entries {
			if headPaths[e.path] && gim.Matches(e.path, false) {
				continue // currently gitignored — won't be in the repo going forward
			}
			if r.scannedBlobs[e.sha] {
				continue // identical content already scanned under another commit/path
			}
			r.scannedBlobs[e.sha] = true
			report.BlobsScanned++

			content, err := readBlob(r, e.sha)
			if err != nil {
				continue
			}
			for _, f := range scanner.ScanBytes(e.path, content, minEntropy) {
				report.Findings = append(report.Findings, Finding{
					CommitSHA:    c.SHA,
					Author:       c.Email,
					Date:         c.Date,
					Path:         e.path,
					Pattern:      f.Pattern,
					Severity:     f.Severity,
					Match:        f.Match,
					DeletedLater: !headPaths[e.path],
				})
			}
		}
	}

	report.Elapsed = time.Since(start)
	return report, nil
}

// --- HEAD / ref resolution ---

func resolveHEAD(gitDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", fmt.Errorf("gitscan: failed to read HEAD: %w", err)
	}
	head := strings.TrimSpace(string(data))

	if !strings.HasPrefix(head, "ref: ") {
		return head, nil // detached HEAD: a raw SHA
	}
	refPath := strings.TrimPrefix(head, "ref: ")

	if data, err := os.ReadFile(filepath.Join(gitDir, refPath)); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Ref not loose (common after `git pack-refs`) — fall back to
	// packed-refs, a flat "<sha> <refname>" text file.
	packed, err := os.ReadFile(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		return "", fmt.Errorf("gitscan: could not resolve ref %q", refPath)
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if strings.HasSuffix(line, " "+refPath) {
			return strings.TrimSpace(strings.SplitN(line, " ", 2)[0]), nil
		}
	}
	return "", fmt.Errorf("gitscan: could not resolve ref %q", refPath)
}

// --- object reading ---

// readObject decompresses a loose object and returns its type ("commit",
// "tree", or "blob") and content, per git's
// "<type> <size>\0<content>" object format.
func readObject(r *repo, sha string) (string, []byte, error) {
	if content, ok := r.objectCache[sha]; ok {
		return r.objectType[sha], content, nil
	}
	if len(sha) != 40 {
		return "", nil, fmt.Errorf("gitscan: malformed object SHA %q", sha)
	}

	path := filepath.Join(r.gitDir, "objects", sha[:2], sha[2:])
	f, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("gitscan: object %s not found (packed objects are not supported)", sha)
	}
	defer f.Close()

	zr, err := zlib.NewReader(f)
	if err != nil {
		return "", nil, fmt.Errorf("gitscan: failed to inflate object %s: %w", sha, err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		return "", nil, fmt.Errorf("gitscan: failed to read object %s: %w", sha, err)
	}

	nul := bytes.IndexByte(raw, 0)
	if nul < 0 {
		return "", nil, fmt.Errorf("gitscan: object %s missing header terminator", sha)
	}
	header := string(raw[:nul])
	content := raw[nul+1:]

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("gitscan: object %s has malformed header %q", sha, header)
	}
	objType := parts[0]

	r.objectCache[sha] = content
	r.objectType[sha] = objType
	return objType, content, nil
}

func readBlob(r *repo, sha string) ([]byte, error) {
	typ, content, err := readObject(r, sha)
	if err != nil {
		return nil, err
	}
	if typ != "blob" {
		return nil, fmt.Errorf("gitscan: object %s is a %s, not a blob", sha, typ)
	}
	return content, nil
}

// --- commit parsing ---

var authorLineRE = regexp.MustCompile(`^(.*) <(.*)> (\d+) ([+-]\d{4})$`)

func parseCommit(sha string, content []byte) (*Commit, error) {
	headerBlock, message, _ := bytes.Cut(content, []byte("\n\n"))

	c := &Commit{SHA: sha, Message: string(message)}
	for _, line := range strings.Split(string(headerBlock), "\n") {
		if line == "" || strings.HasPrefix(line, " ") {
			continue // continuation line of a multiline header (e.g. gpgsig) — not needed here
		}
		key, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch key {
		case "tree":
			c.Tree = rest
		case "parent":
			c.Parents = append(c.Parents, rest)
		case "author":
			if m := authorLineRE.FindStringSubmatch(rest); m != nil {
				c.Author = m[1]
				c.Email = m[2]
				if ts, err := strconv.ParseInt(m[3], 10, 64); err == nil {
					c.Date = time.Unix(ts, 0).UTC()
				}
			}
		}
	}
	if c.Tree == "" {
		return nil, fmt.Errorf("gitscan: commit %s has no tree", sha)
	}
	return c, nil
}

// --- tree parsing ---

// parseTree decodes a tree object's binary entry list: repeated
// "<mode> <name>\0<20-byte-sha>" records concatenated with no delimiter
// between entries.
func parseTree(content []byte) ([]TreeEntry, error) {
	var entries []TreeEntry
	for len(content) > 0 {
		sp := bytes.IndexByte(content, ' ')
		if sp < 0 {
			return nil, fmt.Errorf("gitscan: malformed tree entry (no mode separator)")
		}
		mode := string(content[:sp])

		nul := bytes.IndexByte(content[sp+1:], 0)
		if nul < 0 {
			return nil, fmt.Errorf("gitscan: malformed tree entry (no name terminator)")
		}
		name := string(content[sp+1 : sp+1+nul])

		shaStart := sp + 1 + nul + 1
		if shaStart+20 > len(content) {
			return nil, fmt.Errorf("gitscan: truncated tree entry")
		}
		sha := hex.EncodeToString(content[shaStart : shaStart+20])

		entries = append(entries, TreeEntry{Mode: mode, Name: name, SHA: sha})
		content = content[shaStart+20:]
	}
	return entries, nil
}

type flatEntry struct {
	path string
	sha  string
}

// flattenTree recursively resolves a tree into every regular file it
// (transitively) contains. Submodule gitlinks (mode 160000) are skipped —
// there's no blob to read, just a pointer to another repository.
func flattenTree(r *repo, treeSHA, prefix string) ([]flatEntry, error) {
	typ, content, err := readObject(r, treeSHA)
	if err != nil {
		return nil, err
	}
	if typ != "tree" {
		return nil, fmt.Errorf("gitscan: object %s is a %s, not a tree", treeSHA, typ)
	}
	entries, err := parseTree(content)
	if err != nil {
		return nil, err
	}

	var out []flatEntry
	for _, e := range entries {
		path := e.Name
		if prefix != "" {
			path = prefix + "/" + e.Name
		}
		switch e.Mode {
		case "40000": // subdirectory
			sub, err := flattenTree(r, e.SHA, path)
			if err != nil {
				continue // corrupt/missing subtree — skip it, don't abort the scan
			}
			out = append(out, sub...)
		case "160000": // submodule gitlink — no blob
			continue
		default: // 100644 (regular file), 100755 (executable), 120000 (symlink)
			out = append(out, flatEntry{path: path, sha: e.SHA})
		}
	}
	return out, nil
}

// --- commit history walk ---

// walkCommits performs a breadth-first walk of the commit graph starting
// at headSHA, following every parent (so merge commits contribute both
// sides of history, not just the first parent), until maxCommits distinct
// commits have been visited or history is exhausted.
func walkCommits(r *repo, headSHA string, maxCommits int) ([]*Commit, bool, error) {
	visited := map[string]bool{}
	queue := []string{headSHA}
	var commits []*Commit

	for len(queue) > 0 && len(commits) < maxCommits {
		sha := queue[0]
		queue = queue[1:]
		if visited[sha] {
			continue
		}
		visited[sha] = true

		typ, content, err := readObject(r, sha)
		if err != nil {
			continue // missing object (e.g. shallow clone) — note the gap, keep going
		}
		if typ != "commit" {
			continue
		}
		c, err := parseCommit(sha, content)
		if err != nil {
			continue
		}
		commits = append(commits, c)
		queue = append(queue, c.Parents...)
	}

	sort.SliceStable(commits, func(i, j int) bool { return commits[i].Date.After(commits[j].Date) })
	// Truncated (more history exists beyond what was scanned) whenever the
	// walk stopped because it hit maxCommits with unvisited parents still
	// queued, rather than because history was actually exhausted.
	truncated := len(commits) >= maxCommits && len(queue) > 0
	return commits, truncated, nil
}
