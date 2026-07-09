package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// validRedirectURI applies RFC 9700 §4.1 hygiene: absolute URI, no fragment,
// https required except for loopback (native apps on http://127.0.0.1). This
// holds even in the IdP's dev mode — dev mode relaxes the server's own cookie
// Secure flag, never the security of a client's redirect target.
func validRedirectURI(raw string, _ bool) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "127.0.0.1" || host == "localhost" || host == "::1"
	default:
		// Custom schemes (native app claimed URIs) are accepted.
		return u.Scheme != ""
	}
}

// registrationRequest is the RFC 7591 §2 client metadata we accept.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
}

var allowedGrantTypes = map[string]bool{
	"authorization_code": true,
	"refresh_token":      true,
	"client_credentials": true,
	"urn:ietf:params:oauth:grant-type:device_code": true,
}

// handleRegister implements RFC 7591 dynamic client registration, gated by an
// initial access token (§3): open registration is an abuse vector this
// deployment does not accept.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if s.cfg.RegistrationToken == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "registration_disabled"})
		return
	}
	if !subtleEqual(bearerToken(r), s.cfg.RegistrationToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="registration"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauth.E("invalid_client_metadata", "malformed JSON"))
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, gt := range req.GrantTypes {
		if !allowedGrantTypes[gt] {
			writeJSON(w, http.StatusBadRequest, oauth.E("invalid_client_metadata", "unsupported grant type %q", gt))
			return
		}
	}
	needsRedirects := false
	for _, gt := range req.GrantTypes {
		if gt == "authorization_code" {
			needsRedirects = true
		}
	}
	if needsRedirects && len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, oauth.E("invalid_redirect_uri", "redirect_uris required for authorization_code"))
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u, s.cfg.InsecureDev) {
			writeJSON(w, http.StatusBadRequest, oauth.E("invalid_redirect_uri", "unacceptable redirect_uri %q", u))
			return
		}
	}

	public := req.TokenEndpointAuthMethod == "none"
	clientID := secrets.New("cl_")[:24]
	var secretPlain string
	var secretHash []byte
	if !public {
		secretPlain = secrets.New("cs_")
		sum := sha256.Sum256([]byte(secretPlain))
		secretHash = sum[:]
	}
	scopes := oauth.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = oauth.Scopes{oauth.ScopeOpenID, oauth.ScopeProfile, oauth.ScopeEmail}
	}
	client := storage.Client{
		RealmName:    realm.Name,
		ClientID:     clientID,
		SecretHash:   secretHash,
		Name:         req.ClientName,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Public:       public,
		Scopes:       scopes,
		CreatedAt:    s.now(),
	}
	if err := s.cfg.Store.Clients().Create(r.Context(), client); err != nil {
		writeJSON(w, http.StatusInternalServerError, oauth.E(oauth.ErrServerError, ""))
		return
	}
	resp := map[string]any{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"scope":                      scopes.String(),
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
	}
	if !public {
		// The secret crosses the wire exactly once.
		resp["client_secret"] = secretPlain
	}
	writeJSON(w, http.StatusCreated, resp)
}
