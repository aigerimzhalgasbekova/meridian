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

// Sessions established before the __Host- rename live under the unprefixed
// name at Path=/realms/{realm}. Without a transition, deploying the rename
// logs every user out and — because the new delete path only clears the
// prefixed name at Path=/ — the old cookie could never be expired by the
// server, stranding its session record until TTL. currentSession falls back
// to the legacy name, and every path that clears the session also expires the
// legacy cookie at its original path.
// ponytail: delete the legacy helpers once the longest session TTL has passed
// post-deploy.
func legacySessionCookieName(realm string) string {
	return "idp_session_" + realm
}

func (s *Server) expireLegacySessionCookie(w http.ResponseWriter, realm string) {
	if s.cookiePrefix() == "" {
		return // dev: the legacy name is the current name
	}
	http.SetCookie(w, &http.Cookie{
		Name:     legacySessionCookieName(realm),
		Path:     "/realms/" + realm,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
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
	if (err != nil || c.Value == "") && s.cookiePrefix() != "" {
		c, err = r.Cookie(legacySessionCookieName(realm.Name))
	}
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
	// Any pre-existing session is replaced, not reused — under either name.
	for _, name := range []string{s.sessionCookieName(realm.Name), legacySessionCookieName(realm.Name)} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			_ = s.cfg.Store.Sessions().Delete(r.Context(), realm.Name, secrets.Hash(c.Value))
		}
	}
	s.expireLegacySessionCookie(w, realm.Name)
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
	for _, name := range []string{s.sessionCookieName(realm.Name), legacySessionCookieName(realm.Name)} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			_ = s.cfg.Store.Sessions().Delete(r.Context(), realm.Name, secrets.Hash(c.Value))
		}
	}
	http.SetCookie(w, s.sessionCookie(realm.Name, "", -1))
	s.expireLegacySessionCookie(w, realm.Name)
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
