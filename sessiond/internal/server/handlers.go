package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aikazzh/portfolio/sessiond/internal/store"
)

// maxBody caps request bodies; every payload here is small.
const maxBody = 16 << 10

func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return v, false
	}
	return v, true
}

// storeError maps store sentinels to HTTP. Missing, expired, and revoked
// sessions are indistinguishable on purpose (no validity oracle).
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "unknown or expired session")
	case errors.Is(err, store.ErrSessionLimit):
		writeError(w, http.StatusConflict, "session_limit", "concurrent session limit reached")
	case errors.Is(err, store.ErrBadName):
		writeError(w, http.StatusBadRequest, "invalid_request", store.ErrBadName.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", "")
	}
}

type createRequest struct {
	Realm     string `json:"realm"`
	UserID    string `json:"user_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type sessionResponse struct {
	// Token is returned exactly once, at create/rotate; it is never
	// retrievable again (only its hash is stored).
	Token   string        `json:"token,omitempty"`
	Session store.Session `json:"session"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[createRequest](w, r)
	if !ok {
		return
	}
	token, sess, err := s.store.Create(r.Context(), req.Realm, req.UserID, req.IP, req.UserAgent)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sessionResponse{Token: token, Session: sess})
}

type tokenRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[tokenRequest](w, r)
	if !ok {
		return
	}
	sess, err := s.store.Validate(r.Context(), req.Token)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{Session: sess})
}

type rotateRequest struct {
	Token     string `json:"token"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[rotateRequest](w, r)
	if !ok {
		return
	}
	token, sess, err := s.store.Rotate(r.Context(), req.Token, req.IP, req.UserAgent)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{Token: token, Session: sess})
}

type revokeRequest struct {
	// Exactly one of Token (holder-initiated logout) or ID (admin, from a
	// prior list call) identifies the session.
	Token string `json:"token,omitempty"`
	ID    string `json:"id,omitempty"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[revokeRequest](w, r)
	if !ok {
		return
	}
	var err error
	switch {
	case req.Token != "" && req.ID == "":
		err = s.store.RevokeToken(r.Context(), req.Token)
	case req.ID != "" && req.Token == "":
		err = s.store.RevokeID(r.Context(), req.ID)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "exactly one of token or id required")
		return
	}
	if err != nil {
		storeError(w, err)
		return
	}
	// Revocation is idempotent and non-oracular: always 204.
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.List(r.Context(), r.PathValue("realm"), r.PathValue("user"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleRevokeUser(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.RevokeUser(r.Context(), r.PathValue("realm"), r.PathValue("user"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}
