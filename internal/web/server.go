// Package web implements ZeroVault's local browser dashboard: an
// http.ServeMux router, CSRF protection via net/http's CrossOriginProtection,
// HTTP-only session cookies, and html/template-rendered pages backed by the
// same vault package the CLI uses.
package web

import (
	"log/slog"
	"net/http"
)

// Server holds everything the web dashboard's handlers need.
type Server struct {
	templates templateSet
	sessions  *sessionStore
	vaultPath string
	logger    *slog.Logger
}

// NewServer builds a Server that operates on the vault file at vaultPath.
func NewServer(vaultPath string) (*Server, error) {
	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{
		templates: templates,
		sessions:  newSessionStore(),
		vaultPath: vaultPath,
		logger:    slog.Default(),
	}, nil
}

// Handler builds the full routed, CSRF-protected http.Handler.
func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()

	static, err := staticHandler()
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /static/", static)

	mux.HandleFunc("GET /{$}", s.handleRoot)
	mux.HandleFunc("GET /unlock", s.handleUnlockForm)
	mux.HandleFunc("POST /unlock", s.handleUnlockSubmit)
	mux.HandleFunc("POST /lock", s.requireSession(s.handleLock))

	mux.HandleFunc("GET /dashboard", s.requireSession(s.handleDashboard))
	mux.HandleFunc("GET /entry/{name}", s.requireSession(s.handleEntryView))
	mux.HandleFunc("GET /add", s.requireSession(s.handleAddForm))
	mux.HandleFunc("POST /add", s.requireSession(s.handleAddSubmit))
	mux.HandleFunc("POST /delete/{name}", s.requireSession(s.handleDelete))

	mux.HandleFunc("GET /generate", s.requireSession(s.handleGenerateForm))
	mux.HandleFunc("POST /generate", s.requireSession(s.handleGenerateSubmit))

	mux.HandleFunc("GET /totp", s.requireSession(s.handleTOTPList))
	mux.HandleFunc("POST /totp", s.requireSession(s.handleTOTPAdd))
	mux.HandleFunc("POST /totp/delete/{name}", s.requireSession(s.handleTOTPDelete))

	mux.HandleFunc("GET /scanner", s.requireSession(s.handleScannerForm))
	mux.HandleFunc("POST /scanner", s.requireSession(s.handleScannerSubmit))

	// CrossOriginProtection rejects cross-origin browser requests (via
	// Sec-Fetch-Site, falling back to comparing Origin against Host) to
	// every non-safe-method route — this is the stdlib CSRF defense the
	// kickoff brief calls for, replacing a hand-rolled token scheme.
	protection := http.NewCrossOriginProtection()
	return protection.Handler(mux), nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
