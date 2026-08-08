// Package fakeidp is an in-process OIDC provider used two ways: as the
// upstream for bridge's test suite (no network, no Google/Microsoft accounts)
// and as the built-in upstream in dev mode so the demo runs standalone.
//
// It implements the minimum a real upstream exposes to a Relying Party —
// discovery, JWKS, authorize, token — and auto-approves every authorization
// request as a single configured user. Knobs let tests make it misbehave:
// wrong issuer, wrong nonce, hard failure (for circuit-breaker tests), key
// rotation (for kid-miss refresh tests).
//
// It signs with ES256 rather than RS256 purely because P-256 keygen is
// microseconds and RSA keygen is not; bridge accepts both.
package fakeidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// User is the identity the fake will assert for every login.
type User struct {
	Subject string
	Email   string
	Name    string
}

type codeRec struct {
	nonce       string
	challenge   string
	redirectURI string
}

// Server is a fake upstream OIDC provider backed by httptest.
type Server struct {
	// URL is the issuer base, e.g. http://127.0.0.1:PORT.
	URL string

	ts           *httptest.Server
	clientID     string
	clientSecret string

	mu   sync.Mutex
	key  jose.SigningKey
	pub  jose.VerificationKey
	user User

	failing         bool   // all endpoints return 500
	discoveryIssuer string // issuer field in discovery doc ("" = URL)
	tokenIssuer     string // iss claim in issued tokens ("" = URL)
	nonceOverride   string // nonce claim override ("" = echo the request nonce)
	extraClaims     map[string]any
	extraAudience   []string // aud values beyond the client ID
	unpublishedKey  bool     // sign with a key absent from the JWKS
	codes           map[string]codeRec
}

// New starts a fake upstream for the given RP credentials and user.
// Call Close when done.
func New(clientID, clientSecret string, user User) *Server {
	s := &Server{
		clientID:     clientID,
		clientSecret: clientSecret,
		user:         user,
		codes:        make(map[string]codeRec),
	}
	s.key, s.pub = genKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /token", s.handleToken)
	s.ts = httptest.NewServer(mux)
	s.URL = s.ts.URL
	return s
}

// Close shuts the fake down.
func (s *Server) Close() { s.ts.Close() }

func genKey() (jose.SigningKey, jose.VerificationKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	kidBytes := make([]byte, 8)
	rand.Read(kidBytes)
	kid := hex.EncodeToString(kidBytes)
	return jose.SigningKey{ID: kid, Alg: jose.AlgES256, Private: priv},
		jose.VerificationKey{ID: kid, Alg: jose.AlgES256, Public: &priv.PublicKey}
}

// RotateKeys replaces the signing key with a fresh one. The JWKS serves only
// the new key, simulating an upstream that rotated mid-session: RPs holding
// the old cached JWKS see a kid miss on the next token.
func (s *Server) RotateKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key, s.pub = genKey()
}

// SetFailing makes every endpoint return 500 (true) or restores service.
func (s *Server) SetFailing(v bool) { s.mu.Lock(); s.failing = v; s.mu.Unlock() }

// SetDiscoveryIssuer overrides the issuer value in the discovery document.
func (s *Server) SetDiscoveryIssuer(iss string) { s.mu.Lock(); s.discoveryIssuer = iss; s.mu.Unlock() }

// SetTokenIssuer overrides the iss claim in issued ID tokens.
func (s *Server) SetTokenIssuer(iss string) { s.mu.Lock(); s.tokenIssuer = iss; s.mu.Unlock() }

// SetNonceOverride makes issued tokens carry this nonce instead of the
// request's ("" restores echoing).
func (s *Server) SetNonceOverride(n string) { s.mu.Lock(); s.nonceOverride = n; s.mu.Unlock() }

// SetExtraClaims adds claims (e.g. tid) to issued ID tokens.
func (s *Server) SetExtraClaims(c map[string]any) { s.mu.Lock(); s.extraClaims = c; s.mu.Unlock() }

// SetExtraAudience adds aud values beyond the client ID, producing the
// multi-audience token OIDC Core §3.1.3.7 rule 4 requires an azp alongside.
func (s *Server) SetExtraAudience(aud ...string) { s.mu.Lock(); s.extraAudience = aud; s.mu.Unlock() }

// SetUnpublishedKey makes the fake sign with a key it never publishes in its
// JWKS — a token no refresh can verify.
func (s *Server) SetUnpublishedKey(v bool) { s.mu.Lock(); s.unpublishedKey = v; s.mu.Unlock() }

// SetUser changes the asserted user.
func (s *Server) SetUser(u User) { s.mu.Lock(); s.user = u; s.mu.Unlock() }

func (s *Server) fail(w http.ResponseWriter) bool {
	s.mu.Lock()
	f := s.failing
	s.mu.Unlock()
	if f {
		http.Error(w, "upstream having a bad day", http.StatusInternalServerError)
	}
	return f
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.fail(w) {
		return
	}
	s.mu.Lock()
	iss := s.discoveryIssuer
	s.mu.Unlock()
	if iss == "" {
		iss = s.URL
	}
	writeJSON(w, map[string]string{
		"issuer":                 iss,
		"authorization_endpoint": s.URL + "/authorize",
		"token_endpoint":         s.URL + "/token",
		"jwks_uri":               s.URL + "/jwks",
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if s.fail(w) {
		return
	}
	s.mu.Lock()
	pub := s.pub
	s.mu.Unlock()
	jwk, err := jose.PublicJWK(pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, jose.JWKS{Keys: []jose.JWK{jwk}})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.fail(w) {
		return
	}
	q := r.URL.Query()
	if q.Get("client_id") != s.clientID {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	codeBytes := make([]byte, 16)
	rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)
	s.mu.Lock()
	s.codes[code] = codeRec{
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"),
	}
	s.mu.Unlock()
	// Auto-approve: a real upstream shows a login page here.
	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if s.fail(w) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != s.clientID || r.PostForm.Get("client_secret") != s.clientSecret {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	rec, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	s.mu.Unlock()
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if rec.redirectURI != r.PostForm.Get("redirect_uri") {
		http.Error(w, "invalid_grant: redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != rec.challenge {
		http.Error(w, "invalid_grant: PKCE verification failed", http.StatusBadRequest)
		return
	}
	token, err := s.issueIDToken(rec.nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{
		"id_token":     token,
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
	})
}

func (s *Server) issueIDToken(nonce string) (string, error) {
	s.mu.Lock()
	key, user := s.key, s.user
	iss, nOver, extra, unpub := s.tokenIssuer, s.nonceOverride, s.extraClaims, s.unpublishedKey
	aud := append([]string{s.clientID}, s.extraAudience...)
	s.mu.Unlock()
	if unpub {
		key, _ = genKey()
	}
	if iss == "" {
		iss = s.URL
	}
	if nOver != "" {
		nonce = nOver
	}
	now := time.Now()
	claims := jose.Claims{
		Issuer:    iss,
		Subject:   user.Subject,
		Audience:  aud,
		ExpiresAt: now.Add(time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		Extra: map[string]any{
			"nonce": nonce,
			"email": user.Email,
			// Real upstreams (Google, Entra) send this; bridge refuses to
			// record or forward an email without it. Overridable via extra.
			"email_verified": true,
			"name":           user.Name,
		},
	}
	for k, v := range extra {
		claims.Extra[k] = v
	}
	token, err := jose.SignClaims(claims, key)
	if err != nil {
		return "", fmt.Errorf("fakeidp: sign: %w", err)
	}
	return token, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
