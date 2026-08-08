package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/relay"
)

// Session is a demo-UI login session. AuthTime records the most recent
// upstream authentication; the linking flow demands it be fresh (see
// linkFreshness) so a stolen long-lived cookie cannot quietly attach an
// attacker's provider account to the victim's identity.
type session struct {
	ID         string
	IdentityID string
	Provider   string // provider of the most recent authentication
	AuthTime   time.Time
	Expires    time.Time
}

const (
	sessionCookie = "bridge_sid"
	// flowCookie holds relay.Flow.Binding, scoped to one provider's callback
	// path so a flow started for alpha cannot be completed with beta's cookie
	// and two providers can be in flight at once.
	// ponytail: one cookie per provider path, so two *same-provider* tabs
	// overwrite each other and the first tab's callback fails closed with the
	// uniform error. Key it per flow ID if concurrent same-provider logins
	// ever matter.
	flowCookie = "bridge_flow"
	sessionTTL = 8 * time.Hour
	// linkFreshness is the max age of the session's last upstream
	// authentication for a link flow to start.
	linkFreshness = 5 * time.Minute
)

// sessions is an in-memory session store.
// ponytail: in-memory sessions; sessiond integration when bridge runs multi-node.
type sessions struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]session
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{now: now, m: make(map[string]session)}
}

func (s *sessions) create(identityID, provider string) session {
	b := make([]byte, 32)
	rand.Read(b)
	sess := session{
		ID:         base64.RawURLEncoding.EncodeToString(b),
		IdentityID: identityID,
		Provider:   provider,
		AuthTime:   s.now(),
		Expires:    s.now().Add(sessionTTL),
	}
	s.mu.Lock()
	for id, old := range s.m { // opportunistic sweep
		if s.now().After(old.Expires) {
			delete(s.m, id)
		}
	}
	s.m[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

func (s *sessions) get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok || s.now().After(sess.Expires) {
		return session{}, false
	}
	return sess, true
}

// refresh updates AuthTime after a repeat upstream authentication.
func (s *sessions) refresh(id, provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.AuthTime = s.now()
		sess.Provider = provider
		s.m[id] = sess
	}
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, sess session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.Expires,
		HttpOnly: true,
		Secure:   !s.cfg.InsecureDev,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !s.cfg.InsecureDev, SameSite: http.SameSiteLaxMode,
	})
}

// setFlowCookie hands the flow's binding secret to the browser that started
// it. SameSite must be Lax, not Strict: Strict is not sent on the top-level
// cross-site navigation back from the upstream IdP, which would break every
// login rather than secure it.
func (s *Server) setFlowCookie(w http.ResponseWriter, providerName, binding string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookie,
		Value:    binding,
		Path:     "/callback/" + providerName,
		MaxAge:   int(relay.TTL / time.Second),
		HttpOnly: true,
		Secure:   !s.cfg.InsecureDev,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearFlowCookie retires the binding: a flow is consumed exactly once, so the
// cookie is dead the moment the callback is handled, however it ends.
func (s *Server) clearFlowCookie(w http.ResponseWriter, providerName string) {
	http.SetCookie(w, &http.Cookie{
		Name: flowCookie, Value: "", Path: "/callback/" + providerName, MaxAge: -1,
		HttpOnly: true, Secure: !s.cfg.InsecureDev, SameSite: http.SameSiteLaxMode,
	})
}

// flowBinding reads the binding secret the browser presented ("" if absent,
// which Consume rejects like any other mismatch).
func flowBinding(r *http.Request) string {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// currentSession resolves the request's session cookie, if any.
func (s *Server) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	return s.sessions.get(c.Value)
}
