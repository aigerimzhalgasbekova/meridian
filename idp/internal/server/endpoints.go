package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/token"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

// handleDiscovery serves the OIDC Discovery / RFC 8414 metadata document.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	issuer := s.issuer.IssuerURL(realm.Name)
	doc := map[string]any{
		"issuer":                        issuer,
		"authorization_endpoint":        issuer + "/authorize",
		"token_endpoint":                issuer + "/token",
		"userinfo_endpoint":             issuer + "/userinfo",
		"jwks_uri":                      issuer + "/.well-known/jwks.json",
		"introspection_endpoint":        issuer + "/introspect",
		"revocation_endpoint":           issuer + "/revoke",
		"device_authorization_endpoint": issuer + "/device/code",
		"end_session_endpoint":          issuer + "/logout",
		"response_types_supported":      []string{"code"},
		"grant_types_supported": []string{
			"authorization_code", "refresh_token", "client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		"subject_types_supported": []string{"public"},
		// Must not exceed what keysmith is configured to sign with
		// (KEYSMITH_ALGS, default "EdDSA,RS256"): an RP that trusts this list
		// and gets an alg keysmith cannot produce is a broken integration.
		// Under-advertising is safe, so this tracks keysmith's default rather
		// than its full capability.
		"id_token_signing_alg_values_supported": []string{"EdDSA", "RS256"},
		"scopes_supported": []string{
			oauth.ScopeOpenID, oauth.ScopeProfile, oauth.ScopeEmail, oauth.ScopeOfflineAccess,
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post", "none",
		},
		"code_challenge_methods_supported": []string{"S256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "azp",
			"name", "given_name", "family_name", "preferred_username",
			"email", "email_verified",
		},
		"request_parameter_supported":     false,
		"request_uri_parameter_supported": false,
		"claims_parameter_supported":      false,
	}
	if s.cfg.RegistrationToken != "" {
		doc["registration_endpoint"] = issuer + "/register"
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, doc)
}

// handleJWKS re-publishes keysmith's public key set under the realm issuer,
// so verifiers only ever talk to the issuer they trust.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.realm(w, r); !ok {
		return
	}
	raw, err := s.cfg.Keysmith.RawJWKS(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "keys_unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(raw)
}

// bearerToken extracts an RFC 6750 bearer token from the request.
func bearerToken(r *http.Request) string {
	if h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return h
	}
	return ""
}

func unauthorizedBearer(w http.ResponseWriter, code, description string) {
	// RFC 6750 §3: challenge with machine-readable error attributes.
	w.Header().Set("WWW-Authenticate",
		`Bearer realm="userinfo", error="`+code+`", error_description="`+description+`"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": code})
}

// handleUserinfo implements OIDC Core §5.3.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	raw := bearerToken(r)
	if raw == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		raw = r.PostFormValue("access_token")
	}
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_request"})
		return
	}
	claims, err := s.cfg.Keysmith.Verify(r.Context(), raw, jose.Expect{
		Issuer:   s.issuer.IssuerURL(realm.Name),
		Audience: "meridian",
		Now:      s.cfg.Now,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		unauthorizedBearer(w, "invalid_token", "token verification failed")
		return
	}
	scopes := oauth.ParseScopes(stringClaim(claims.Extra, "scope"))
	if !scopes.Has(oauth.ScopeOpenID) {
		unauthorizedBearer(w, "insufficient_scope", "openid scope required")
		return
	}
	user, err := s.cfg.Store.Users().Get(r.Context(), realm.Name, claims.Subject)
	if err != nil || user.Disabled {
		unauthorizedBearer(w, "invalid_token", "unknown subject")
		return
	}
	out := map[string]any{"sub": user.ID}
	for k, v := range token.ProfileClaims(user, scopes) {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func stringClaim(extra map[string]any, key string) string {
	if v, ok := extra[key].(string); ok {
		return v
	}
	return ""
}

// handleIntrospect implements RFC 7662. Caller must be an authenticated
// (confidential) client of the realm; the response is {"active": false} for
// anything not verifiable — no detail leaks.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "malformed form body"), false)
		return
	}
	caller, basicAttempted, authErr := s.authenticateClient(r, realm.Name)
	if authErr != nil {
		oauth.WriteTokenError(w, authErr, basicAttempted)
		return
	}
	if caller.Public {
		// §2.1: the endpoint must not be an oracle for unauthenticated
		// parties; public clients cannot hold credentials.
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidClient, "introspection requires a confidential client"), false)
		return
	}
	presented := r.PostFormValue("token")
	if presented == "" {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "token is required"), false)
		return
	}
	inactive := func() { writeJSON(w, http.StatusOK, map[string]any{"active": false}) }

	// Try as a JWT access token first.
	if claims, err := s.cfg.Keysmith.Verify(r.Context(), presented, jose.Expect{
		Issuer:   s.issuer.IssuerURL(realm.Name),
		Audience: "meridian",
		Now:      s.cfg.Now,
		Leeway:   30 * time.Second,
	}); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     true,
			"token_type": "Bearer",
			"iss":        claims.Issuer,
			"sub":        claims.Subject,
			"aud":        claims.Audience,
			"exp":        claims.ExpiresAt,
			"iat":        claims.IssuedAt,
			"jti":        claims.ID,
			"scope":      stringClaim(claims.Extra, "scope"),
			"client_id":  stringClaim(claims.Extra, "azp"),
		})
		return
	}

	// Then as a refresh token.
	rt, err := s.cfg.Store.RefreshTokens().Get(r.Context(), realm.Name, secrets.Hash(presented))
	if err != nil || rt.Revoked || !rt.RotatedAt.IsZero() || s.now().After(rt.ExpiresAt) {
		inactive()
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"token_type": "refresh_token",
		"sub":        rt.UserID,
		"exp":        rt.ExpiresAt.Unix(),
		"iat":        rt.CreatedAt.Unix(),
		"scope":      rt.Scopes.String(),
		"client_id":  rt.ClientID,
	})
}

// handleRevoke implements RFC 7009. Refresh tokens revoke their whole family.
// Access tokens are stateless JWTs and cannot be individually revoked; per
// §2.2.1 the server answers unsupported_token_type for them.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "malformed form body"), false)
		return
	}
	caller, basicAttempted, authErr := s.authenticateClient(r, realm.Name)
	if authErr != nil {
		oauth.WriteTokenError(w, authErr, basicAttempted)
		return
	}
	presented := r.PostFormValue("token")
	if presented == "" {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "token is required"), false)
		return
	}

	// A structurally valid JWT from our issuer is an access token we cannot
	// revoke — say so honestly rather than returning a misleading 200.
	if _, err := s.cfg.Keysmith.Verify(r.Context(), presented, jose.Expect{
		Issuer: s.issuer.IssuerURL(realm.Name), Audience: "meridian",
		Now: s.cfg.Now, Leeway: 30 * time.Second,
	}); err == nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrUnsupportedTokenType,
			"access tokens are stateless; bound by their short TTL"), false)
		return
	}

	rt, err := s.cfg.Store.RefreshTokens().Get(r.Context(), realm.Name, secrets.Hash(presented))
	if err != nil {
		// §2.2: invalid tokens yield 200 — revocation is idempotent and
		// must not become a token-validity oracle.
		w.WriteHeader(http.StatusOK)
		return
	}
	if rt.ClientID != caller.ClientID {
		// Not this client's token: same silent 200, but flag it.
		s.cfg.Logger.Warn("revocation attempt for another client's token",
			"realm", realm.Name, "caller", caller.ClientID, "owner", rt.ClientID)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.cfg.Store.RefreshTokens().RevokeFamily(r.Context(), realm.Name, rt.FamilyID); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrServerError, ""), false)
		return
	}
	w.WriteHeader(http.StatusOK)
}
