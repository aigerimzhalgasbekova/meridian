package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Healthy means: an active signing key exists for the default algorithm.
	if _, err := s.manager.SigningKey(r.Context(), s.cfg.DefaultAlg); err != nil {
		writeError(w, http.StatusServiceUnavailable, "no_active_key", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.manager.JWKS(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	body, err := json.Marshal(set)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.cfg.JWKSMaxAge.Seconds())))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

type signRequest struct {
	// Claims is the flat claims object to sign. exp/iat are set by the
	// server; supplying them is an error (they would silently lie).
	Claims json.RawMessage `json:"claims"`
	// TTLSeconds bounds the token lifetime; capped by MaxTokenTTL.
	TTLSeconds int64 `json:"ttl_seconds"`
	// Alg selects the signing algorithm; defaults to the server default.
	Alg string `json:"alg,omitempty"`
}

type signResponse struct {
	Token     string `json:"token"`
	KeyID     string `json:"kid"`
	Alg       string `json:"alg"`
	ExpiresAt int64  `json:"exp"`
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(req.Claims) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "claims required")
		return
	}
	var claims jose.Claims
	if err := json.Unmarshal(req.Claims, &claims); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "claims: "+err.Error())
		return
	}
	if claims.ExpiresAt != 0 || claims.IssuedAt != 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "exp and iat are set by the server")
		return
	}
	if req.TTLSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be positive")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl > s.cfg.MaxTokenTTL {
		writeError(w, http.StatusBadRequest, "ttl_too_long",
			fmt.Sprintf("ttl %v exceeds maximum %v", ttl, s.cfg.MaxTokenTTL))
		return
	}
	alg := s.cfg.DefaultAlg
	if req.Alg != "" {
		alg = jose.Algorithm(req.Alg)
		if !alg.Supported() {
			writeError(w, http.StatusBadRequest, "invalid_request", "unsupported alg")
			return
		}
	}
	now := s.cfg.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()

	sk, err := s.manager.SigningKey(r.Context(), alg)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no_active_key", err.Error())
		return
	}
	token, err := jose.SignClaims(claims, sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", "")
		return
	}
	writeJSON(w, http.StatusOK, signResponse{
		Token: token, KeyID: sk.ID, Alg: string(sk.Alg), ExpiresAt: claims.ExpiresAt,
	})
}

type verifyRequest struct {
	Token    string `json:"token"`
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
}

type verifyResponse struct {
	Valid  bool            `json:"valid"`
	Claims json.RawMessage `json:"claims,omitempty"`
	Reason string          `json:"reason,omitempty"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}
	set, err := s.manager.VerificationSet(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	claims, err := jose.VerifyClaims(req.Token, set,
		[]jose.Algorithm{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256},
		jose.Expect{Issuer: req.Issuer, Audience: req.Audience, Now: s.cfg.Now, Leeway: 30 * time.Second})
	if err != nil {
		// Verification failure is a *successful* API call with valid=false.
		// The reason is coarse by design: detailed failure modes are an
		// oracle for attackers refining forgeries.
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Reason: coarseReason(err)})
		return
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: true, Claims: raw})
}

func coarseReason(err error) string {
	switch {
	case errors.Is(err, jose.ErrExpired):
		return "expired"
	case errors.Is(err, jose.ErrNotYetValid), errors.Is(err, jose.ErrIssuedInFuture):
		return "not_yet_valid"
	default:
		return "invalid"
	}
}

type keyView struct {
	ID         string     `json:"id"`
	Alg        string     `json:"alg"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	PromotedAt *time.Time `json:"promoted_at,omitempty"`
	RetiringAt *time.Time `json:"retiring_at,omitempty"`
	RetiredAt  *time.Time `json:"retired_at,omitempty"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.manager.Keys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	views := make([]keyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, keyView{
			ID: k.ID, Alg: string(k.Alg), State: string(k.State),
			CreatedAt: k.CreatedAt, PromotedAt: optTime(k.PromotedAt),
			RetiringAt: optTime(k.RetiringAt), RetiredAt: optTime(k.RetiredAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": views})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alg string `json:"alg"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	alg := jose.Algorithm(req.Alg)
	if !alg.Supported() {
		writeError(w, http.StatusBadRequest, "invalid_request", "unsupported alg")
		return
	}
	k, err := s.manager.Generate(r.Context(), alg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate_failed", "")
		return
	}
	writeJSON(w, http.StatusCreated, keyView{
		ID: k.ID, Alg: string(k.Alg), State: string(k.State), CreatedAt: k.CreatedAt,
	})
}

func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Force bool `json:"force"`
	}
	// Body is optional; absence means force=false.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	id := r.PathValue("id")
	err := s.manager.Promote(r.Context(), id, req.Force)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "promoted", "id": id})
	case errors.Is(err, keystore.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "")
	case errors.Is(err, keystore.ErrNotPending):
		writeError(w, http.StatusConflict, "not_pending", err.Error())
	case errors.Is(err, keystore.ErrDwellNotElapsed):
		writeError(w, http.StatusConflict, "dwell_not_elapsed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", "")
	}
}
