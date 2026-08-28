package web

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	vcrypto "zerovault/internal/crypto"
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
