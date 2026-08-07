package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/idp/internal/token"
)

// tokenResponse is the RFC 6749 §5.1 success payload.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "malformed form body"), false)
		return
	}

	client, basicAttempted, authErr := s.authenticateClient(r, realm.Name)
	if authErr != nil {
		oauth.WriteTokenError(w, authErr, basicAttempted)
		return
	}

	grantType := r.PostFormValue("grant_type")
	if !client.AllowsGrant(grantType) && grantType != "" {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrUnauthorizedClient,
			"client is not authorized for grant type %q", grantType), false)
		return
	}

	var (
		resp *tokenResponse
		oerr *oauth.Error
	)
	switch grantType {
	case "authorization_code":
		resp, oerr = s.grantAuthorizationCode(r, realm, client)
	case "refresh_token":
		resp, oerr = s.grantRefreshToken(r, realm, client)
	case "client_credentials":
		resp, oerr = s.grantClientCredentials(r, realm, client)
	case "urn:ietf:params:oauth:grant-type:device_code":
		resp, oerr = s.grantDeviceCode(r, realm, client)
	case "":
		oerr = oauth.E(oauth.ErrInvalidRequest, "grant_type is required")
	default:
		oerr = oauth.E(oauth.ErrUnsupportedGrantType, "unsupported grant_type %q", grantType)
	}
	if oerr != nil {
		oauth.WriteTokenError(w, oerr, false)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// authenticateClient implements RFC 6749 §2.3: client_secret_basic (§2.3.1,
// with the mandated form-urlencoding of credentials), client_secret_post, and
// unauthenticated public clients identified by client_id.
func (s *Server) authenticateClient(r *http.Request, realm string) (storage.Client, bool, *oauth.Error) {
	var clientID, clientSecret string
	basicAttempted := false

	if user, pass, ok := r.BasicAuth(); ok {
		basicAttempted = true
		id, err1 := url.QueryUnescape(user)
		sec, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return storage.Client{}, true, oauth.E(oauth.ErrInvalidClient, "malformed basic credentials")
		}
		clientID, clientSecret = id, sec
		// Using both Basic and form credentials is an error (§2.3).
		if r.PostFormValue("client_secret") != "" || (r.PostFormValue("client_id") != "" && r.PostFormValue("client_id") != clientID) {
			return storage.Client{}, true, oauth.E(oauth.ErrInvalidRequest, "multiple client authentication methods")
		}
	} else {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}
	if clientID == "" {
		return storage.Client{}, basicAttempted, oauth.E(oauth.ErrInvalidClient, "client authentication required")
	}

	client, err := s.cfg.Store.Clients().Get(r.Context(), realm, clientID)
	if err != nil {
		// Equalize with the found-client path before failing.
		dummy := sha256.Sum256([]byte(clientSecret))
		subtle.ConstantTimeCompare(dummy[:], dummy[:])
		return storage.Client{}, basicAttempted, oauth.E(oauth.ErrInvalidClient, "unknown client")
	}
	if client.Public {
		if clientSecret != "" {
			return storage.Client{}, basicAttempted, oauth.E(oauth.ErrInvalidClient, "public client must not send a secret")
		}
		return client, basicAttempted, nil
	}
	if clientSecret == "" {
		return storage.Client{}, basicAttempted, oauth.E(oauth.ErrInvalidClient, "client authentication required")
	}
	got := sha256.Sum256([]byte(clientSecret))
	if subtle.ConstantTimeCompare(got[:], client.SecretHash) != 1 {
		return storage.Client{}, basicAttempted, oauth.E(oauth.ErrInvalidClient, "invalid client credentials")
	}
	return client, basicAttempted, nil
}

func (s *Server) grantAuthorizationCode(r *http.Request, realm storage.Realm, client storage.Client) (*tokenResponse, *oauth.Error) {
	ctx := r.Context()
	code := r.PostFormValue("code")
	if code == "" {
		return nil, oauth.E(oauth.ErrInvalidRequest, "code is required")
	}
	ac, err := s.cfg.Store.AuthCodes().Consume(ctx, secrets.Hash(code), s.now())
	switch {
	case errors.Is(err, storage.ErrConsumed):
		// Replay: revoke everything the first redemption issued (RFC 9700).
		if ac.IssuedFamilyID != "" {
			_ = s.cfg.Store.RefreshTokens().RevokeFamily(ctx, realm.Name, ac.IssuedFamilyID)
		}
		s.cfg.Logger.Warn("authorization code replay detected",
			"realm", realm.Name, "client_id", ac.ClientID)
		return nil, oauth.E(oauth.ErrInvalidGrant, "code already redeemed")
	case err != nil:
		return nil, oauth.E(oauth.ErrInvalidGrant, "invalid or expired code")
	}
	if ac.ClientID != client.ClientID || ac.RealmName != realm.Name {
		return nil, oauth.E(oauth.ErrInvalidGrant, "code was not issued to this client")
	}
	// redirect_uri must match the authorization request (§4.1.3) — but it is
	// REQUIRED here only if the authorization request carried it. handleAuthorize
	// backfills the sole registered URI when it is omitted, so a conforming
	// single-URI client omits it at both endpoints; accept that, since the
	// registered URI is then unambiguous and already bound to the code.
	presentedRedirect := r.PostFormValue("redirect_uri")
	if presentedRedirect == "" && len(client.RedirectURIs) == 1 && client.RedirectURIs[0] == ac.RedirectURI {
		presentedRedirect = ac.RedirectURI
	}
	if ac.RedirectURI != presentedRedirect {
		return nil, oauth.E(oauth.ErrInvalidGrant, "redirect_uri mismatch")
	}
	// PKCE (RFC 7636 §4.6). A code bound to a challenge requires a valid
	// verifier; a verifier against an unbound code is rejected too.
	verifier := r.PostFormValue("code_verifier")
	if ac.CodeChallenge != "" {
		if !oauth.VerifyPKCE(ac.CodeChallenge, verifier) {
			return nil, oauth.E(oauth.ErrInvalidGrant, "PKCE verification failed")
		}
	} else if verifier != "" {
		return nil, oauth.E(oauth.ErrInvalidGrant, "code_verifier provided but code has no challenge")
	}

	user, err := s.cfg.Store.Users().Get(ctx, realm.Name, ac.UserID)
	if err != nil || user.Disabled {
		return nil, oauth.E(oauth.ErrInvalidGrant, "user unavailable")
	}

	return s.issueUserTokens(ctx, realm, client, user, ac.Scopes, ac.AuthTime, ac.Nonce, ac.CodeHash)
}

// issueUserTokens mints the access/ID/refresh token set for a user grant.
func (s *Server) issueUserTokens(ctx context.Context, realm storage.Realm, client storage.Client, user storage.User, scopes oauth.Scopes, authTime time.Time, nonce, codeHash string) (*tokenResponse, *oauth.Error) {
	access, err := s.issuer.AccessToken(ctx, token.AccessTokenInput{
		Realm: realm, ClientID: client.ClientID, UserID: user.ID,
		Scopes: scopes, AuthTime: authTime,
	})
	if err != nil {
		s.cfg.Logger.Error("access token signing failed", "err", err)
		return nil, oauth.E(oauth.ErrServerError, "")
	}
	resp := &tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(realm.AccessTokenTTL.Seconds()),
		Scope:       scopes.String(),
	}
	if scopes.Has(oauth.ScopeOpenID) {
		idt, err := s.issuer.IDToken(ctx, token.IDTokenInput{
			Realm: realm, ClientID: client.ClientID, User: user,
			Nonce: nonce, AuthTime: authTime, Scopes: scopes,
		})
		if err != nil {
			s.cfg.Logger.Error("id token signing failed", "err", err)
			return nil, oauth.E(oauth.ErrServerError, "")
		}
		resp.IDToken = idt
	}
	if scopes.Has(oauth.ScopeOfflineAccess) {
		plaintext, rt := token.NewRefreshToken(realm, client.ClientID, user.ID, scopes, authTime, nonce, s.now())
		if err := s.cfg.Store.RefreshTokens().Create(ctx, rt); err != nil {
			return nil, oauth.E(oauth.ErrServerError, "")
		}
		if codeHash != "" {
			// Link code → family for replay revocation.
			_ = s.cfg.Store.AuthCodes().MarkFamily(ctx, codeHash, rt.FamilyID)
		}
		resp.RefreshToken = plaintext
	}
	return resp, nil
}

func (s *Server) grantRefreshToken(r *http.Request, realm storage.Realm, client storage.Client) (*tokenResponse, *oauth.Error) {
	ctx := r.Context()
	presented := r.PostFormValue("refresh_token")
	if presented == "" {
		return nil, oauth.E(oauth.ErrInvalidRequest, "refresh_token is required")
	}
	hash := secrets.Hash(presented)
	rt, err := s.cfg.Store.RefreshTokens().Get(ctx, realm.Name, hash)
	if err != nil {
		return nil, oauth.E(oauth.ErrInvalidGrant, "invalid refresh token")
	}
	if rt.ClientID != client.ClientID {
		// A token presented by the wrong client is indistinguishable from
		// theft; kill the family.
		_ = s.cfg.Store.RefreshTokens().RevokeFamily(ctx, realm.Name, rt.FamilyID)
		s.cfg.Logger.Warn("refresh token presented by wrong client",
			"realm", realm.Name, "owner", rt.ClientID, "presenter", client.ClientID)
		return nil, oauth.E(oauth.ErrInvalidGrant, "invalid refresh token")
	}
	if rt.Revoked {
		return nil, oauth.E(oauth.ErrInvalidGrant, "invalid refresh token")
	}
	if s.now().After(rt.ExpiresAt) {
		return nil, oauth.E(oauth.ErrInvalidGrant, "refresh token expired")
	}
	if !rt.RotatedAt.IsZero() {
		// Reuse of a rotated generation: theft detected (RFC 9700 §4.14.2).
		_ = s.cfg.Store.RefreshTokens().RevokeFamily(ctx, realm.Name, rt.FamilyID)
		s.cfg.Logger.Warn("refresh token reuse detected — family revoked",
			"realm", realm.Name, "client_id", client.ClientID, "family", rt.FamilyID)
		return nil, oauth.E(oauth.ErrInvalidGrant, "invalid refresh token")
	}

	// Optional scope narrowing (§6): requested must be a subset.
	scopes := rt.Scopes
	if requested := oauth.ParseScopes(r.PostFormValue("scope")); len(requested) > 0 {
		if len(requested.Subtract(rt.Scopes)) > 0 {
			return nil, oauth.E(oauth.ErrInvalidScope, "requested scope exceeds original grant")
		}
		scopes = requested
	}

	user, err := s.cfg.Store.Users().Get(ctx, realm.Name, rt.UserID)
	if err != nil || user.Disabled {
		_ = s.cfg.Store.RefreshTokens().RevokeFamily(ctx, realm.Name, rt.FamilyID)
		return nil, oauth.E(oauth.ErrInvalidGrant, "user unavailable")
	}

	// Mint and sign everything BEFORE committing the rotation. Signing is a
	// remote keysmith call; a transient failure must leave the presented
	// refresh token valid and un-rotated so the client can safely retry.
	// Committing the rotation first would trip reuse detection (~:238) on that
	// retry and force a family-wide logout — turning a keysmith blip into a
	// permanent logout. Reuse-detection semantics are unchanged: Rotate below
	// remains the single atomic consume point (including the ErrConsumed
	// lost-race path).
	newPlain, successor := token.RotateRefreshToken(rt, s.now())
	access, err := s.issuer.AccessToken(ctx, token.AccessTokenInput{
		Realm: realm, ClientID: client.ClientID, UserID: user.ID,
		Scopes: scopes, AuthTime: rt.AuthTime,
	})
	if err != nil {
		return nil, oauth.E(oauth.ErrServerError, "")
	}
	resp := &tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(realm.AccessTokenTTL.Seconds()),
		RefreshToken: newPlain,
		Scope:        scopes.String(),
	}
	if scopes.Has(oauth.ScopeOpenID) {
		// OIDC Core §12.2: refreshed ID tokens carry no nonce.
		idt, err := s.issuer.IDToken(ctx, token.IDTokenInput{
			Realm: realm, ClientID: client.ClientID, User: user,
			AuthTime: rt.AuthTime, Scopes: scopes,
		})
		if err != nil {
			return nil, oauth.E(oauth.ErrServerError, "")
		}
		resp.IDToken = idt
	}

	// Commit the rotation LAST: the atomic consume-and-insert. A failure here
	// means the successor was never persisted and its plaintext is discarded.
	if err := s.cfg.Store.RefreshTokens().Rotate(ctx, realm.Name, hash, successor, s.now()); err != nil {
		if errors.Is(err, storage.ErrConsumed) {
			// Lost the race with another redemption of the same token —
			// same treatment as reuse.
			_ = s.cfg.Store.RefreshTokens().RevokeFamily(ctx, realm.Name, rt.FamilyID)
			return nil, oauth.E(oauth.ErrInvalidGrant, "invalid refresh token")
		}
		return nil, oauth.E(oauth.ErrServerError, "")
	}
	return resp, nil
}

func (s *Server) grantClientCredentials(r *http.Request, realm storage.Realm, client storage.Client) (*tokenResponse, *oauth.Error) {
	if client.Public {
		return nil, oauth.E(oauth.ErrUnauthorizedClient, "public clients cannot use client_credentials")
	}
	scopes := oauth.ParseScopes(r.PostFormValue("scope"))
	if scopes.Has(oauth.ScopeOpenID) || scopes.Has(oauth.ScopeOfflineAccess) {
		return nil, oauth.E(oauth.ErrInvalidScope, "openid/offline_access are user scopes")
	}
	if invalid := scopes.Subtract(client.Scopes); len(invalid) > 0 {
		return nil, oauth.E(oauth.ErrInvalidScope, "scope not allowed: %s", invalid.String())
	}
	access, err := s.issuer.AccessToken(r.Context(), token.AccessTokenInput{
		Realm: realm, ClientID: client.ClientID, Scopes: scopes,
	})
	if err != nil {
		return nil, oauth.E(oauth.ErrServerError, "")
	}
	return &tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(realm.AccessTokenTTL.Seconds()),
		Scope:       scopes.String(),
	}, nil
}
