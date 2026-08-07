package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// Session cookies are realm-scoped by name so realms stay isolated in the
// browser too, and carry the __Host- prefix so a sibling subdomain cannot
// "toss" a same-named Domain-scoped cookie at us: browsers order cookies by
// descending path length (RFC 6265 §5.4.2) and r.Cookie takes the first match,
// so a tossed cookie at a longer path would otherwise outrank the real session
// — session fixation that never touches establishSession. __Host- forbids
// Domain, mandates Path=/ and mandates Secure; since dev mode serves plain
// HTTP, dev keeps the unprefixed names (a browser would reject the prefixed
// ones there).
func (s *Server) cookiePrefix() string {
	if s.cfg.InsecureDev {
		return ""
	}
	return "__Host-"
}

func (s *Server) sessionCookieName(realm string) string {
	return s.cookiePrefix() + "idp_session_" + realm
}

func (s *Server) sessionCookie(realm, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     s.sessionCookieName(realm),
		Value:    value,
		Path:     "/", // mandated by __Host-; the realm lives in the name
		HttpOnly: true,
		Secure:   !s.cfg.InsecureDev,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	}
}

// currentSession resolves the request's login session, if any.
func (s *Server) currentSession(r *http.Request, realm storage.Realm) (storage.Session, storage.User, error) {
	c, err := r.Cookie(s.sessionCookieName(realm.Name))
	if err != nil || c.Value == "" {
		return storage.Session{}, storage.User{}, errors.New("no session cookie")
	}
	sess, err := s.cfg.Store.Sessions().Get(r.Context(), realm.Name, secrets.Hash(c.Value))
	if err != nil {
		return storage.Session{}, storage.User{}, err
	}
	if s.now().After(sess.ExpiresAt) {
		_ = s.cfg.Store.Sessions().Delete(r.Context(), realm.Name, sess.IDHash)
		return storage.Session{}, storage.User{}, errors.New("session expired")
	}
	user, err := s.cfg.Store.Users().Get(r.Context(), realm.Name, sess.UserID)
	if err != nil || user.Disabled {
		return storage.Session{}, storage.User{}, errors.New("user unavailable")
	}
	return sess, user, nil
}

// establishSession creates a fresh session for user and sets the cookie.
// Always a new session ID — never adopts one from the request (fixation
// defense).
func (s *Server) establishSession(w http.ResponseWriter, r *http.Request, realm storage.Realm, userID string) error {
	// Any pre-existing session is replaced, not reused.
	if c, err := r.Cookie(s.sessionCookieName(realm.Name)); err == nil && c.Value != "" {
		_ = s.cfg.Store.Sessions().Delete(r.Context(), realm.Name, secrets.Hash(c.Value))
	}
	id := secrets.New("sid_")
	now := s.now()
	sess := storage.Session{
		IDHash:          secrets.Hash(id),
		RealmName:       realm.Name,
		UserID:          userID,
		CreatedAt:       now,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(realm.SessionTTL),
	}
	if err := s.cfg.Store.Sessions().Create(r.Context(), sess); err != nil {
		return err
	}
	http.SetCookie(w, s.sessionCookie(realm.Name, id, realm.SessionTTL))
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if c, err := r.Cookie(s.sessionCookieName(realm.Name)); err == nil && c.Value != "" {
		_ = s.cfg.Store.Sessions().Delete(r.Context(), realm.Name, secrets.Hash(c.Value))
	}
	http.SetCookie(w, s.sessionCookie(realm.Name, "", -1))
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// csrfCookieName holds the double-submit CSRF token for pre-login forms. It
// carries the same __Host- protection as the session cookie: a tossed CSRF
// cookie plus its value in the form is login-CSRF.
func (s *Server) csrfCookieName(realm string) string {
	return s.cookiePrefix() + "idp_csrf_" + realm
}

// ensureCSRF returns the CSRF token for the request, minting one if needed.
func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request, realm string) string {
	if c, err := r.Cookie(s.csrfCookieName(realm)); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := secrets.New("")
	http.SetCookie(w, &http.Cookie{
		Name:     s.csrfCookieName(realm),
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.InsecureDev,
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// checkCSRF validates the double-submit pair on form POSTs.
func (s *Server) checkCSRF(r *http.Request, realm string) bool {
	c, err := r.Cookie(s.csrfCookieName(realm))
	if err != nil || c.Value == "" {
		return false
	}
	return subtleEqual(c.Value, r.PostFormValue("csrf_token"))
}
