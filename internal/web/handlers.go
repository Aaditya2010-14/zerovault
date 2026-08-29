package web

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	vcrypto "zerovault/internal/crypto"
	"zerovault/internal/fileenc"
	"zerovault/internal/gitscan"
	"zerovault/internal/health"
	"zerovault/internal/qrcode"
	"zerovault/internal/scanner"
	"zerovault/internal/totp"
	"zerovault/internal/vault"
)

// baseData carries the fields every page template needs (nav state, flash
// messages). Page-specific data structs embed it so its fields are
// promoted and visible to html/template directly.
type baseData struct {
	Title         string
	Authenticated bool
	Error         string
	Success       string
}

// --- Unlock / lock ---

func (s *Server) handleUnlockForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "unlock", struct {
		baseData
		VaultExists bool
	}{
		baseData:    baseData{Title: "Unlock"},
		VaultExists: vault.Exists(s.vaultPath),
	})
}

func (s *Server) handleUnlockSubmit(w http.ResponseWriter, r *http.Request) {
	// Rate limiting: this is the only throttle on master-password guessing
	// through the web UI (PBKDF2's own cost is the first line of defense).
	// A global counter is enough here because the threat model treats the
	// loopback interface as a single trust boundary — see README.
	if wait := s.unlockLimit.delay(); wait > 0 {
		time.Sleep(wait)
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")

	var v *vault.Vault
	if vault.Exists(s.vaultPath) {
		loaded, err := vault.Load(s.vaultPath, password)
		if err != nil {
			s.unlockLimit.recordFailure()
			s.renderUnlockError(w, "incorrect master password")
			return
		}
		s.unlockLimit.recordSuccess()
		v = loaded
	} else {
		if password == "" || password != r.FormValue("confirm") {
			s.renderUnlockError(w, "passwords do not match or are empty")
			return
		}
		v = vault.New()
		if err := vault.Save(s.vaultPath, password, v); err != nil {
			s.renderUnlockError(w, "failed to create vault")
			return
		}
	}

	token, err := s.sessions.create(v, password, s.vaultPath)
	if err != nil {
		http.Error(w, "failed to start session", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token)
	http.Redirect(w, r, "/about", http.StatusSeeOther)
}

func (s *Server) renderUnlockError(w http.ResponseWriter, msg string) {
	s.render(w, "unlock", struct {
		baseData
		VaultExists bool
	}{
		baseData:    baseData{Title: "Unlock", Error: msg},
		VaultExists: vault.Exists(s.vaultPath),
	})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.delete(cookie.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/unlock", http.StatusSeeOther)
}

// saveSession re-encrypts and persists the session's in-memory vault back
// to disk after a mutation.
func (s *Server) saveSession(sess *session) error {
	return vault.Save(sess.vaultPath, sess.masterPw, sess.vault)
}

// --- Dashboard / entries ---

// strengthClass maps a health.Strength to the weak/fair/strong CSS tier
// used by the strength badges and colored left borders across the
// dashboard, entry detail, and generator pages.
func strengthClass(s health.Strength) string {
	switch s {
	case health.Weak:
		return "weak"
	case health.Fair:
		return "fair"
	default:
		return "strong"
	}
}

// relativeDays renders a duration as a short human-friendly age string.
func relativeDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", days)
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	report := health.Analyze(sess.vault, time.Now())

	classes := make(map[string]string, len(report.Entries))
	for _, e := range report.Entries {
		classes[e.Name] = strengthClass(e.Strength)
	}

	s.render(w, "dashboard", struct {
		baseData
		Entries       []*vault.Entry
		StrengthClass map[string]string
		TOTPCount     int
		HealthScore   int
		HealthClass   string
	}{
		baseData:      baseData{Title: "Vault", Authenticated: true},
		Entries:       sess.vault.List(),
		StrengthClass: classes,
		TOTPCount:     len(sess.vault.ListTOTP()),
		HealthScore:   report.Score,
		HealthClass:   healthScoreClass(report.Score),
	})
}

// healthScoreClass buckets a 0-100 health score into the same
// good/warning/critical tiers health.html has always used.
func healthScoreClass(score int) string {
	switch {
	case score < 50:
		return "critical"
	case score < 80:
		return "warning"
	default:
		return "good"
	}
}

func (s *Server) handleEntryView(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	entry, err := sess.vault.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	now := time.Now()
	report := health.Analyze(sess.vault, now)
	var eh health.EntryHealth
	for _, e := range report.Entries {
		if e.Name == name {
			eh = e
			break
		}
	}

	age := now.Sub(entry.UpdatedAt)
	s.render(w, "view", struct {
		baseData
		Entry         *vault.Entry
		Bits          float64
		Strength      health.Strength
		StrengthClass string
		Missing       []string
		CreatedRel    string
		UpdatedRel    string
		StaleDays     int
		Stale         bool
	}{
		baseData:      baseData{Title: name, Authenticated: true},
		Entry:         entry,
		Bits:          eh.Bits,
		Strength:      eh.Strength,
		StrengthClass: strengthClass(eh.Strength),
		Missing:       missingCharClasses(entry.Password),
		CreatedRel:    relativeDays(now.Sub(entry.CreatedAt)),
		UpdatedRel:    relativeDays(age),
		StaleDays:     int(age.Hours() / 24),
		Stale:         age > 90*24*time.Hour,
	})
}

// missingCharClasses lists the character classes absent from password, for
// display as concrete "what to add" hints next to the strength meter.
func missingCharClasses(password string) []string {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	var missing []string
	if !hasUpper {
		missing = append(missing, "no uppercase letters")
	}
	if !hasLower {
		missing = append(missing, "no lowercase letters")
	}
	if !hasDigit {
		missing = append(missing, "no digits")
	}
	if !hasSymbol {
		missing = append(missing, "no symbols")
	}
	return missing
}

func (s *Server) handleAddForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "add", baseData{Title: "Add Entry", Authenticated: true})
}

func (s *Server) handleEntryEditForm(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	entry, err := sess.vault.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	s.render(w, "edit", struct {
		baseData
		Entry *vault.Entry
	}{
		baseData: baseData{Title: "Edit " + name, Authenticated: true},
		Entry:    entry,
	})
}

func (s *Server) handleEntryEditSubmit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	url := r.FormValue("url")
	notes := r.FormValue("notes")

	// Update() leaves any blank field unchanged, so only the fields
	// actually supplied need validating against Add's same limits.
	for _, f := range []struct {
		name, value string
		max         int
	}{
		{"password", password, maxPasswordLen},
		{"username", username, maxUsernameLen},
		{"url", url, maxURLLen},
		{"notes", notes, maxNotesLen},
	} {
		if f.value == "" {
			continue
		}
		if err := validateFieldLen(f.name, f.value, f.max); err != nil {
			entry, _ := sess.vault.Get(name)
			s.render(w, "edit", struct {
				baseData
				Entry *vault.Entry
			}{baseData{Title: "Edit " + name, Authenticated: true, Error: err.Error()}, entry})
			return
		}
	}

	if _, err := sess.vault.Update(name, username, password, url, notes); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault after edit", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}

	if password != "" && health.IsBreached(password) {
		entry, _ := sess.vault.Get(name)
		s.render(w, "edit", struct {
			baseData
			Entry *vault.Entry
		}{baseData{
			Title: "Edit " + name, Authenticated: true,
			Success: "Entry updated.",
			Error:   "Warning: this password appears in known breach databases. Consider using a generated password instead.",
		}, entry})
		return
	}
	http.Redirect(w, r, "/entry/"+name, http.StatusSeeOther)
}

func (s *Server) handleAddSubmit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	username := r.FormValue("username")
	password := r.FormValue("password")
	url := r.FormValue("url")
	notes := r.FormValue("notes")

	if err := validateAddEntry(name, username, password, url, notes); err != nil {
		s.render(w, "add", struct {
			baseData
		}{baseData{Title: "Add Entry", Authenticated: true, Error: err.Error()}})
		return
	}

	if _, err := sess.vault.Add(name, username, password, url, notes); err != nil {
		s.render(w, "add", struct {
			baseData
		}{baseData{Title: "Add Entry", Authenticated: true, Error: err.Error()}})
		return
	}

	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault after add", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}

	if health.IsBreached(password) {
		s.render(w, "add", struct {
			baseData
		}{baseData{
			Title: "Add Entry", Authenticated: true,
			Success: fmt.Sprintf("Entry %q added.", name),
			Error:   "Warning: this password appears in known breach databases. Consider using a generated password instead.",
		}})
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// validateAddEntry applies the server-side field limits documented in the
// threat model, independent of html/template's output-side escaping — this
// keeps malformed data out of the vault file rather than only neutralizing
// it at render time.
func validateAddEntry(name, username, password, url, notes string) error {
	if err := validateEntryName(name); err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if err := validateFieldLen("password", password, maxPasswordLen); err != nil {
		return err
	}
	if err := validateFieldLen("username", username, maxUsernameLen); err != nil {
		return err
	}
	if err := validateFieldLen("url", url, maxURLLen); err != nil {
		return err
	}
	if err := validateFieldLen("notes", notes, maxNotesLen); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	if err := sess.vault.Delete(name); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// --- Password generator ---

func (s *Server) handleGenerateForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "generate", generateData{
		baseData: baseData{Title: "Generate Password", Authenticated: true},
		Length:   20, Upper: true, Lower: true, Digits: true, Symbols: true,
	})
}

type generateData struct {
	baseData
	Length                        int
	Upper, Lower, Digits, Symbols bool
	Generated                     string
	Bits                          float64
	Strength                      health.Strength
	StrengthClass                 string
	UpperCount, LowerCount        int
	DigitCount, SymbolCount       int
	CrackTimeOnline               string // 10 guesses/sec — a rate-limited login form
	CrackTimeOffline              string // 10B guesses/sec — an offline GPU attack on a stolen hash
	BreachChecked                 bool   // always true once a password has been generated
	Breached                      bool   // should always be false for a truly random password — shown as proof of thoroughness
}

func (s *Server) handleGenerateSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	length, err := strconv.Atoi(r.FormValue("length"))
	if err != nil || length <= 0 {
		length = 20
	}
	data := generateData{
		baseData: baseData{Title: "Generate Password", Authenticated: true},
		Length:   length,
		Upper:    r.FormValue("upper") == "on",
		Lower:    r.FormValue("lower") == "on",
		Digits:   r.FormValue("digits") == "on",
		Symbols:  r.FormValue("symbols") == "on",
	}

	pw, err := vcrypto.GeneratePassword(vcrypto.PasswordOptions{
		Length: length, Upper: data.Upper, Lower: data.Lower, Digits: data.Digits, Symbols: data.Symbols,
	})
	if err != nil {
		data.Error = err.Error()
		s.render(w, "generate", data)
		return
	}
	data.Generated = pw
	data.BreachChecked = true
	data.Breached = health.IsBreached(pw)
	if size := vcrypto.AlphabetSize(vcrypto.PasswordOptions{
		Upper: data.Upper, Lower: data.Lower, Digits: data.Digits, Symbols: data.Symbols,
	}); size > 0 {
		data.Bits = float64(length) * math.Log2(float64(size))
	}
	data.Strength = health.Classify(data.Bits)
	data.StrengthClass = strengthClass(data.Strength)
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			data.UpperCount++
		case r >= 'a' && r <= 'z':
			data.LowerCount++
		case r >= '0' && r <= '9':
			data.DigitCount++
		default:
			data.SymbolCount++
		}
	}
	combinations := math.Pow(2, data.Bits)
	data.CrackTimeOnline = crackTimeEstimate(combinations, 10)
	data.CrackTimeOffline = crackTimeEstimate(combinations, 10e9)
	s.render(w, "generate", data)
}

// crackTimeEstimate renders an average-case (half the keyspace) brute-force
// time at the given guesses/sec rate as a human-scale string.
func crackTimeEstimate(combinations, guessesPerSecond float64) string {
	seconds := combinations / 2 / guessesPerSecond
	const (
		minute = 60.0
		hour   = 60 * minute
		day    = 24 * hour
		year   = 365.25 * day
	)
	switch {
	case seconds < 1:
		return "instantly"
	case seconds < minute:
		return fmt.Sprintf("~%.0f seconds", seconds)
	case seconds < hour:
		return fmt.Sprintf("~%.0f minutes", seconds/minute)
	case seconds < day:
		return fmt.Sprintf("~%.0f hours", seconds/hour)
	case seconds < year:
		return fmt.Sprintf("~%.0f days", seconds/day)
	case seconds < 1e6*year:
		return fmt.Sprintf("~%.0f years", seconds/year)
	case seconds < 1e12*year:
		return fmt.Sprintf("~%s million years", scaleMagnitude(seconds/year/1e6))
	default:
		return fmt.Sprintf("~%s billion years", scaleMagnitude(seconds/year/1e9))
	}
}

// scaleMagnitude renders n as a fixed-point number, switching to
// "mantissa x 10^exponent" scientific notation once n would otherwise print
// with more than 9 digits before the decimal point — brute-force estimates
// on a long, high-entropy password are astronomically large numbers that are
// unreadable (and misleadingly precise-looking) spelled out in full.
func scaleMagnitude(n float64) string {
	if n < 1e9 {
		return fmt.Sprintf("%.1f", n)
	}
	exp := int(math.Floor(math.Log10(n)))
	mantissa := n / math.Pow(10, float64(exp))
	return fmt.Sprintf("%.3f x 10^%d", mantissa, exp)
}

// --- TOTP ---

type totpRow struct {
	Name string
	Code string
}

func (s *Server) handleTOTPList(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	entries := sess.vault.ListTOTP()

	rows := make([]totpRow, 0, len(entries))
	for _, e := range entries {
		code, err := e.CurrentCode()
		if err != nil {
			continue
		}
		rows = append(rows, totpRow{Name: e.Name, Code: code})
	}

	s.render(w, "totp", struct {
		baseData
		Entries   []totpRow
		Remaining int
	}{
		baseData:  baseData{Title: "TOTP Codes", Authenticated: true},
		Entries:   rows,
		Remaining: totp.RemainingSeconds(time.Now()),
	})
}

func (s *Server) handleTOTPAdd(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if err := validateEntryName(name); err != nil {
		s.render(w, "totp", struct {
			baseData
			Entries   []totpRow
			Remaining int
		}{baseData: baseData{Title: "TOTP Codes", Authenticated: true, Error: err.Error()}})
		return
	}

	_, err := sess.vault.AddTOTP(name, r.FormValue("secret"), totp.DefaultDigits, totp.DefaultPeriod)
	if err != nil {
		s.render(w, "totp", struct {
			baseData
			Entries   []totpRow
			Remaining int
		}{baseData: baseData{Title: "TOTP Codes", Authenticated: true, Error: err.Error()}})
		return
	}

	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/totp", http.StatusSeeOther)
}

func (s *Server) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	if err := sess.vault.DeleteTOTP(name); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/totp", http.StatusSeeOther)
}

// handleTOTPQR renders an entry's enrollment QR code as inline SVG — the
// same otpauth:// URI and zero-dependency encoder the `zerovault totp qr`
// CLI command uses, just served instead of written to a file.
func (s *Server) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	entry, err := sess.vault.GetTOTP(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	uri := otpauthURI(entry.Name, entry.Secret)
	m, err := qrcode.Encode([]byte(uri))
	if err != nil {
		s.logger.Error("failed to generate TOTP QR code", "error", err)
		http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, qrcode.ToSVG(m))
}

// otpauthURI builds the standard otpauth:// URI a phone authenticator app's
// QR scanner expects (Key URI Format, as used by Google Authenticator etc).
func otpauthURI(name, secret string) string {
	label := "ZeroVault:" + name
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", "ZeroVault")
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

// --- Scanner ---

// scanResult normalizes scanner.Finding and gitscan.Finding into one shape
// so the results template doesn't need two separate render paths.
type scanResult struct {
	Severity     scanner.Severity
	Location     string // "config.py:3" for file mode, commit-relative path for git mode
	Pattern      string
	Match        string
	IsGit        bool
	CommitSHA    string
	Author       string
	Date         string
	DeletedLater bool
}

type scannerData struct {
	baseData
	Mode          string // "file" or "git"
	Path          string
	MinEntropy    float64
	GitDepth      int
	Scanned       bool
	Results       []scanResult
	CriticalCount int
	WarningCount  int
	ElapsedMS     int64
	FilesScanned  int // file mode: files touched; git mode: commits scanned
	Patterns      []scanner.Pattern
}

func newScannerData(mode string) scannerData {
	return scannerData{
		baseData:   baseData{Title: "Secrets Scanner", Authenticated: true},
		Mode:       mode,
		MinEntropy: scanner.MinEntropy,
		GitDepth:   50,
		Patterns:   scanner.Patterns,
	}
}

func (s *Server) handleScannerForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "scanner", newScannerData("file"))
}

func (s *Server) handleScannerSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	path := r.FormValue("path")
	mode := r.FormValue("mode")
	if mode != "git" {
		mode = "file"
	}

	minEntropy, err := strconv.ParseFloat(r.FormValue("min_entropy"), 64)
	if err != nil || minEntropy < 2.0 || minEntropy > 5.0 {
		minEntropy = scanner.MinEntropy
	}
	gitDepth, err := strconv.Atoi(r.FormValue("git_depth"))
	if err != nil || gitDepth <= 0 {
		gitDepth = 50
	}

	data := newScannerData(mode)
	data.Path = path
	data.MinEntropy = minEntropy
	data.GitDepth = gitDepth
	data.Scanned = true

	if err := validateScanPath(path); err != nil {
		data.Error = err.Error()
		data.Scanned = false
		s.render(w, "scanner", data)
		return
	}

	start := time.Now()
	if mode == "git" {
		report, err := gitscan.ScanRepo(path, gitDepth, minEntropy)
		if err != nil {
			data.Error = err.Error()
			data.Scanned = false
			s.render(w, "scanner", data)
			return
		}
		data.FilesScanned = report.CommitsScanned
		for _, f := range report.Findings {
			data.Results = append(data.Results, scanResult{
				Severity:     f.Severity,
				Location:     f.Path,
				Pattern:      f.Pattern,
				Match:        f.Match,
				IsGit:        true,
				CommitSHA:    f.CommitSHA[:min(8, len(f.CommitSHA))],
				Author:       f.Author,
				Date:         f.Date.Format("2006-01-02"),
				DeletedLater: f.DeletedLater,
			})
		}
	} else {
		findings, err := scanner.ScanDir(path, scanner.Options{MinEntropy: minEntropy})
		if err != nil {
			data.Error = "an error occurred while scanning"
			data.Scanned = false
			s.logger.Error("scan failed", "path", path, "error", err)
			s.render(w, "scanner", data)
			return
		}
		seenFiles := map[string]bool{}
		for _, f := range findings {
			seenFiles[f.File] = true
			data.Results = append(data.Results, scanResult{
				Severity: f.Severity,
				Location: fmt.Sprintf("%s:%d", f.File, f.Line),
				Pattern:  f.Pattern,
				Match:    f.Match,
			})
		}
		data.FilesScanned = len(seenFiles)
	}
	data.ElapsedMS = time.Since(start).Milliseconds()

	for _, res := range data.Results {
		if res.Severity == scanner.SeverityCritical {
			data.CriticalCount++
		} else {
			data.WarningCount++
		}
	}
	s.render(w, "scanner", data)
}

// --- Password health ---

type healthData struct {
	baseData
	Report     health.Report
	ScoreClass string
	Strong     []health.EntryHealth
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	report := health.Analyze(sess.vault, time.Now())

	scoreClass := "good"
	if report.Score < 50 {
		scoreClass = "critical"
	} else if report.Score < 80 {
		scoreClass = "warning"
	}

	var strong []health.EntryHealth
	for _, e := range report.Entries {
		if e.Strength >= health.Strong {
			strong = append(strong, e)
		}
	}

	s.render(w, "health", healthData{
		baseData:   baseData{Title: "Password Health", Authenticated: true},
		Report:     report,
		ScoreClass: scoreClass,
		Strong:     strong,
	})
}

// --- About ---

// stdlibSubstitutions is the count of third-party packages replaced with
// standard-library equivalents, documented one-by-one in STDLIB.md.
const stdlibSubstitutions = 20

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	s.render(w, "about", struct {
		baseData
		StdlibSubstitutions int
	}{
		baseData:            baseData{Title: "About", Authenticated: true},
		StdlibSubstitutions: stdlibSubstitutions,
	})
}

// --- Security audit ---
//
// The web package never imports the attacks package directly: attacks
// itself imports internal/web to drive its own test harness (it spins up
// a real web.Server for the web-attack tests), so a direct import back
// would be a package cycle. Instead cli.cmdServe wires AuditRunner and
// AuditLastResult into this package at startup, once both packages exist.

// AuditResult is one attack's outcome, in a form the audit page can render
// without this package depending on the attacks package's types.
type AuditResult struct {
	Category    string
	Name        string
	Description string
	Methodology string
	Passed      bool
	StatusLabel string
	Detail      string
	Duration    string
}

// AuditSnapshot is a full attack-suite run, ready for template rendering.
type AuditSnapshot struct {
	RanAt   time.Time
	Results []AuditResult
}

// AuditRunner executes the attack suite and returns its results. Set by
// cli.cmdServe before the server starts handling requests.
var AuditRunner func() (AuditSnapshot, error)

// AuditLastResult returns the most recently completed run, if any. Set by
// cli.cmdServe before the server starts handling requests.
var AuditLastResult func() (AuditSnapshot, bool)

type auditData struct {
	baseData
	HasReport bool
	RanAt     string
	Total     int
	Passed    int
	Failed    int
	Verdict   string
	Results   []AuditResult
}

func buildAuditData(title string, snap AuditSnapshot, ok bool) auditData {
	data := auditData{baseData: baseData{Title: title, Authenticated: true}}
	if !ok {
		return data
	}
	data.HasReport = true
	data.RanAt = snap.RanAt.Format("2006-01-02 15:04:05")
	data.Results = snap.Results
	for _, r := range snap.Results {
		data.Total++
		if r.Passed {
			data.Passed++
		} else {
			data.Failed++
		}
	}
	if data.Failed > 0 {
		data.Verdict = "VULNERABILITIES FOUND"
	} else {
		data.Verdict = "SECURE"
	}
	return data
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if AuditLastResult == nil {
		http.Error(w, "audit runner not configured", http.StatusInternalServerError)
		return
	}
	snap, ok := AuditLastResult()
	s.render(w, "audit", buildAuditData("Security Audit", snap, ok))
}

func (s *Server) handleAuditRun(w http.ResponseWriter, r *http.Request) {
	if AuditRunner == nil {
		http.Error(w, "audit runner not configured", http.StatusInternalServerError)
		return
	}
	if _, err := AuditRunner(); err != nil {
		data := buildAuditData("Security Audit", AuditSnapshot{}, false)
		data.Error = "Failed to run security audit: " + err.Error()
		s.render(w, "audit", data)
		return
	}
	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// --- Settings / master password rotation ---

type settingsData struct {
	baseData
	VaultPath    string
	VaultSize    int64
	EntryCount   int
	TOTPCount    int
	NotesCount   int
	LastModified string
	GoVersion    string
}

// buildSettingsData gathers the read-only vault-info stats shown on the
// settings page — file stat plus counts already available from the
// in-memory vault, nothing new persisted or computed at rest.
func (s *Server) buildSettingsData(sess *session, title string) settingsData {
	data := settingsData{
		baseData:  baseData{Title: title, Authenticated: true},
		VaultPath: sess.vaultPath,
		GoVersion: runtime.Version(),
	}
	if info, err := os.Stat(sess.vaultPath); err == nil {
		data.VaultSize = info.Size()
		data.LastModified = info.ModTime().Format("2006-01-02 15:04 MST")
	}
	for _, e := range sess.vault.List() {
		data.EntryCount++
		if e.Notes != "" {
			data.NotesCount++
		}
	}
	data.TOTPCount = len(sess.vault.ListTOTP())
	return data
}

func (s *Server) handleSettingsForm(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "settings", s.buildSettingsData(sess, "Settings"))
}

func (s *Server) handleSettingsRekey(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		data := s.buildSettingsData(sess, "Settings")
		data.Error = msg
		s.render(w, "settings", data)
	}

	if current != sess.masterPw {
		fail("current password is incorrect")
		return
	}
	if newPw == "" || newPw != confirm {
		fail("new passwords do not match or are empty")
		return
	}

	if _, err := vault.Rekey(sess.vaultPath, current, newPw); err != nil {
		s.logger.Error("rekey failed", "error", err)
		fail("failed to change master password")
		return
	}

	// The old session's masterPw is now stale (the vault is re-encrypted
	// under a different key) — force re-authentication rather than
	// letting the session limp along with a password that no longer
	// matches what's on disk.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.delete(cookie.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/unlock", http.StatusSeeOther)
}

// handleSettingsExportEncrypted streams the vault file exactly as it sits
// on disk — still AES-256-GCM encrypted under the current master
// password, so the download is only useful to someone who also has it.
func (s *Server) handleSettingsExportEncrypted(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := filepath.Base(sess.vaultPath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeFile(w, r, sess.vaultPath)
}

// handleSettingsExportJSON serializes the decrypted vault straight to
// JSON — an intentionally plaintext export, clearly labeled as such in
// the UI, for migrating to another password manager.
func (s *Server) handleSettingsExportJSON(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	w.Header().Set("Content-Disposition", `attachment; filename="zerovault-export.json"`)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sess.vault); err != nil {
		s.logger.Error("json export failed", "error", err)
	}
}

// handleSettingsDeleteAll wipes every entry and TOTP secret from the vault
// and saves the (now empty) result. The confirmation dialog lives
// client-side (data-confirm), same pattern as entry deletion.
func (s *Server) handleSettingsDeleteAll(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	sess.vault.Entries = nil
	sess.vault.TOTPEntries = nil
	if err := s.saveSession(sess); err != nil {
		s.logger.Error("failed to save vault after delete-all", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	data := s.buildSettingsData(sess, "Settings")
	data.Success = "All vault data has been deleted."
	s.render(w, "settings", data)
}

// --- File encryption ---

const maxUploadSize = 200 * 1024 * 1024 // 200MB — generous for a demo, bounded to avoid an unbounded upload DoS

func (s *Server) handleFileForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "file", baseData{Title: "File Encryption", Authenticated: true})
}

// handleFileEncrypt receives an uploaded file, encrypts it with fileenc
// (the same AES-256-GCM + PBKDF2 pipeline the CLI's `encrypt` command
// uses), and streams the result back as a download — nothing is written
// to a path the browser could collide with, since the ciphertext only
// ever exists in a server-side temp file cleaned up before the handler
// returns.
func (s *Server) handleFileEncrypt(w http.ResponseWriter, r *http.Request) {
	s.handleFileOp(w, r, true)
}

func (s *Server) handleFileDecrypt(w http.ResponseWriter, r *http.Request) {
	s.handleFileOp(w, r, false)
}

func (s *Server) handleFileOp(w http.ResponseWriter, r *http.Request, encrypt bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.renderFileError(w, "upload too large or malformed (200MB limit)")
		return
	}
	defer r.MultipartForm.RemoveAll()

	password := r.FormValue("password")
	if password == "" {
		s.renderFileError(w, "password cannot be empty")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.renderFileError(w, "no file uploaded")
		return
	}
	defer file.Close()

	tmpDir, err := os.MkdirTemp("", "zerovault-fileop-*")
	if err != nil {
		s.logger.Error("failed to create temp dir", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, filepath.Base(header.Filename))
	inFile, err := os.Create(inPath)
	if err != nil {
		s.logger.Error("failed to create temp file", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(inFile, file); err != nil {
		inFile.Close()
		s.logger.Error("failed to buffer upload", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	inFile.Close()

	var (
		outPath    string
		outName    string
		opErr      error
		bytesTotal int64
	)
	if encrypt {
		outPath = inPath + ".enc"
		opErr = fileenc.EncryptFile(inPath, outPath, password, nil, nil)
		outName = header.Filename + ".enc"
	} else {
		// Empty outPath lets fileenc recover the original filename from the
		// encrypted file's own metadata (placed alongside inPath, i.e. in
		// tmpDir — never a path the browser could collide with).
		outPath, opErr = fileenc.DecryptFile(inPath, "", password, nil, nil)
		if opErr == nil {
			outName = filepath.Base(outPath)
		}
	}
	if opErr != nil {
		s.renderFileError(w, opErr.Error())
		return
	}

	outFile, err := os.Open(outPath)
	if err != nil {
		s.logger.Error("failed to open result file", "error", err)
		http.Error(w, "an error occurred", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()
	if info, err := outFile.Stat(); err == nil {
		bytesTotal = info.Size()
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", outName))
	w.Header().Set("Content-Length", strconv.FormatInt(bytesTotal, 10))
	io.Copy(w, outFile)
}

func (s *Server) renderFileError(w http.ResponseWriter, msg string) {
	s.render(w, "file", struct {
		baseData
	}{baseData{Title: "File Encryption", Authenticated: true, Error: msg}})
}
