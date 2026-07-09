// Package oauth implements protocol-level OAuth 2.0 primitives: the RFC 6749
// error vocabulary, scope handling, and PKCE (RFC 7636).
package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ErrorCode is an OAuth 2.0 error code. The set and semantics come from
// RFC 6749 §4.1.2.1 (authorization endpoint) and §5.2 (token endpoint), plus
// RFC 8628 §3.5 (device flow) and RFC 7009 §2.2.1 (revocation).
type ErrorCode string

const (
	ErrInvalidRequest          ErrorCode = "invalid_request"
	ErrInvalidClient           ErrorCode = "invalid_client"
	ErrInvalidGrant            ErrorCode = "invalid_grant"
	ErrUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrUnsupportedGrantType    ErrorCode = "unsupported_grant_type"
	ErrInvalidScope            ErrorCode = "invalid_scope"
	ErrAccessDenied            ErrorCode = "access_denied"
	ErrUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrServerError             ErrorCode = "server_error"
	ErrTemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	// OIDC Core §3.1.2.6
	ErrLoginRequired       ErrorCode = "login_required"
	ErrInteractionRequired ErrorCode = "interaction_required"
	// RFC 8628 §3.5
	ErrAuthorizationPending ErrorCode = "authorization_pending"
	ErrSlowDown             ErrorCode = "slow_down"
	ErrExpiredToken         ErrorCode = "expired_token"
	// RFC 7009 §2.2.1
	ErrUnsupportedTokenType ErrorCode = "unsupported_token_type"
)

// Error is an OAuth 2.0 protocol error.
type Error struct {
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description,omitempty"`
}

func (e *Error) Error() string {
	if e.Description == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// E builds an *Error.
func E(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Description: fmt.Sprintf(format, args...)}
}

// tokenEndpointStatus maps error codes to HTTP status per RFC 6749 §5.2:
// invalid_client uses 401 (with WWW-Authenticate when Basic was attempted),
// everything else uses 400.
func tokenEndpointStatus(code ErrorCode) int {
	switch code {
	case ErrInvalidClient:
		return http.StatusUnauthorized
	case ErrServerError:
		return http.StatusInternalServerError
	case ErrTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// WriteTokenError renders err as a token-endpoint JSON error (RFC 6749 §5.2).
// basicAttempted controls the WWW-Authenticate challenge on invalid_client.
func WriteTokenError(w http.ResponseWriter, err *Error, basicAttempted bool) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err.Code == ErrInvalidClient && basicAttempted {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	w.WriteHeader(tokenEndpointStatus(err.Code))
	_ = json.NewEncoder(w).Encode(err)
}

// RedirectError sends the error back to the client's redirect_uri per
// RFC 6749 §4.1.2.1. Only call this after the redirect_uri has been
// validated — errors from an unvalidated redirect_uri must never redirect
// (open-redirect hazard); render those with WritePageError instead.
func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, err *Error, state string) {
	q := redirectURI.Query()
	q.Set("error", string(err.Code))
	if err.Description != "" {
		q.Set("error_description", err.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u := *redirectURI
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
