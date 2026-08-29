package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"zerovault/internal/vault"
)

// sessionTTL is how long an unlocked session stays valid without any
// activity before it's treated as locked again.
const sessionTTL = 15 * time.Minute

const sessionCookieName = "zerovault_session"

// session holds a decrypted, in-memory vault for the duration of one
// unlocked browser session. The master password is kept only in memory
// (never written to disk or logged) so the vault can be re-encrypted and
// saved after mutations.
//
// mu serializes every request that touches this session: the same session
// (same browser, or the same account open in two tabs) can receive
// genuinely concurrent requests, and sess.vault's Entries/TOTPEntries are
// plain slices with no synchronization of their own — a concurrent
// append/read (e.g. one tab adding an entry while another lists them) is a
// real data race that can panic mid-JSON-marshal, and two concurrent Save
// calls also collide on the same on-disk temp file. requireSession holds
// mu for the whole handler, which trades a little concurrency for
// correctness — acceptable here since this is a single-user local
// dashboard, not a multi-tenant server.
type session struct {
	mu        sync.Mutex
	vault     *vault.Vault
	masterPw  string
	vaultPath string
	expiresAt time.Time

	// pendingTOTPSecret holds a freshly generated (not-yet-confirmed) 2FA
	// secret between GET /settings/2fa/setup and POST /settings/2fa/confirm
	// — kept only in memory for this session, never persisted unless the
	// user actually confirms a valid code.
	pendingTOTPSecret string
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*session)}
}

func (s *sessionStore) create(v *vault.Vault, masterPw, vaultPath string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("web: failed to generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &session{
		vault:     v,
		masterPw:  masterPw,
		vaultPath: vaultPath,
		expiresAt: time.Now().Add(sessionTTL),
	}
	return token, nil
}

// get returns the session for token if it exists and hasn't expired,
// sliding its expiry forward on access.
func (s *sessionStore) get(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.expiresAt) {
		delete(s.sessions, token)
		return nil, false
	}
	sess.expiresAt = time.Now().Add(sessionTTL)
	return sess, true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

type contextKey int

const sessionContextKey contextKey = 0

func sessionFromContext(r *http.Request) *session {
	sess, _ := r.Context().Value(sessionContextKey).(*session)
	return sess
}

// requireSession redirects to /unlock when there's no valid, unexpired
// session cookie — every vault-touching route goes through this.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/unlock", http.StatusSeeOther)
			return
		}
		sess, ok := s.sessions.get(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/unlock", http.StatusSeeOther)
			return
		}
		// Serialize every request against this session — see the mu field
		// comment on session for why this is necessary, not just cautious.
		sess.mu.Lock()
		defer sess.mu.Unlock()
		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
		// Secure is intentionally not set: the dashboard is documented as
		// localhost-only HTTP in the threat model, so there is no TLS
		// session to mark the cookie Secure against.
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// --- Pending two-factor challenges ---
//
// When a vault has 2FA enabled, a correct master password isn't enough to
// start a real session — it only proves the password was right. The
// already-decrypted vault and password are held here, keyed by a short-
// lived token in their own cookie, until a matching TOTP code arrives.
// Nothing about this state is reachable without first passing the
// password check, so a wrong password can never reveal whether 2FA is
// enabled.

const pendingCookieName = "zerovault_pending_2fa"
const pendingTTL = 3 * time.Minute

type pendingUnlock struct {
	vault     *vault.Vault
	masterPw  string
	expiresAt time.Time
}

type pendingStore struct {
	mu      sync.Mutex
	pending map[string]*pendingUnlock
}

func newPendingStore() *pendingStore {
	return &pendingStore{pending: make(map[string]*pendingUnlock)}
}

func (p *pendingStore) create(v *vault.Vault, masterPw string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("web: failed to generate 2fa challenge token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[token] = &pendingUnlock{
		vault:     v,
		masterPw:  masterPw,
		expiresAt: time.Now().Add(pendingTTL),
	}
	return token, nil
}

func (p *pendingStore) get(token string) (*pendingUnlock, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pend, ok := p.pending[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(pend.expiresAt) {
		delete(p.pending, token)
		return nil, false
	}
	return pend, true
}

func (p *pendingStore) delete(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, token)
}

func setPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(pendingTTL.Seconds()),
	})
}

func clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
