package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	vcrypto "zerovault/internal/crypto"
	"zerovault/internal/fileenc"
	"zerovault/internal/health"
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
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "dashboard", struct {
		baseData
		Entries []*vault.Entry
	}{
		baseData: baseData{Title: "Vault", Authenticated: true},
		Entries:  sess.vault.List(),
	})
}

func (s *Server) handleEntryView(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	name := r.PathValue("name")

	entry, err := sess.vault.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	s.render(w, "view", struct {
		baseData
		Entry *vault.Entry
	}{
		baseData: baseData{Title: name, Authenticated: true},
		Entry:    entry,
	})
}

func (s *Server) handleAddForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "add", baseData{Title: "Add Entry", Authenticated: true})
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
	s.render(w, "generate", data)
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

// --- Scanner ---

func (s *Server) handleScannerForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "scanner", scannerData{baseData: baseData{Title: "Secrets Scanner", Authenticated: true}})
}

type scannerData struct {
	baseData
	Path     string
	Scanned  bool
	Findings []scanner.Finding
}

func (s *Server) handleScannerSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	path := r.FormValue("path")

	data := scannerData{
		baseData: baseData{Title: "Secrets Scanner", Authenticated: true},
		Path:     path,
		Scanned:  true,
	}

	if err := validateScanPath(path); err != nil {
		data.Error = err.Error()
		data.Scanned = false
		s.render(w, "scanner", data)
		return
	}

	findings, err := scanner.ScanDir(path, scanner.Options{})
	if err != nil {
		data.Error = "an error occurred while scanning"
		data.Scanned = false
		s.logger.Error("scan failed", "path", path, "error", err)
		s.render(w, "scanner", data)
		return
	}
	data.Findings = findings
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

// --- Settings / master password rotation ---

func (s *Server) handleSettingsForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings", baseData{Title: "Settings", Authenticated: true})
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

	if current != sess.masterPw {
		s.render(w, "settings", baseData{Title: "Settings", Authenticated: true, Error: "current password is incorrect"})
		return
	}
	if newPw == "" || newPw != confirm {
		s.render(w, "settings", baseData{Title: "Settings", Authenticated: true, Error: "new passwords do not match or are empty"})
		return
	}

	if _, err := vault.Rekey(sess.vaultPath, current, newPw); err != nil {
		s.logger.Error("rekey failed", "error", err)
		s.render(w, "settings", baseData{Title: "Settings", Authenticated: true, Error: "failed to change master password"})
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
