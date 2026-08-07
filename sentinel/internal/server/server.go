// Package server implements sentinel's HTTP surface.
//
// Route map:
//
//	GET  /healthz                liveness (unauthenticated)
//	POST /v1/check               combined rate-limit + lockout + risk decision
//	POST /v1/report-auth-result  feed back an auth outcome (lockout + risk history)
//	POST /v1/events              append an arbitrary event to the audit chain
//	GET  /v1/audit/verify        walk the chain, report the first broken link
//
// All /v1 routes require a static bearer token, compared in constant time.
// Sentinel is an internal decision service consumed by other Meridian
// services (idp's LoginGuard); a shared service token matches keysmith's
// house pattern, and mTLS or per-caller tokens are a deployment concern, not
// a code one.
//
// Decision semantics for /v1/check: rate limit and lockout are hard gates
// (deny with Retry-After); only when both pass does the risk score choose
// between allow / challenge / deny. Every decision is appended to the audit
// chain — the decision log IS the compliance evidence.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aikazzh/portfolio/sentinel/audit"
	"github.com/aikazzh/portfolio/sentinel/lockout"
	"github.com/aikazzh/portfolio/sentinel/ratelimit"
	"github.com/aikazzh/portfolio/sentinel/risk"
)

// Config assembles a Server. All components are required except Logger.
type Config struct {
	// Token authenticates callers of /v1 routes.
	Token    string
	Limiter  *ratelimit.Limiter
	Lockouts *lockout.Tracker
	Risk     *risk.Engine
	Audit    *audit.Log
	Logger   *slog.Logger
	Now      func() time.Time
}

// Server is the sentinel HTTP server.
type Server struct {
	cfg     Config
	handler http.Handler
}

// New builds the server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /v1/check", s.auth(s.handleCheck))
	mux.Handle("POST /v1/report-auth-result", s.auth(s.handleReportAuthResult))
	mux.Handle("POST /v1/events", s.auth(s.handleEvents))
	mux.Handle("GET /v1/audit/verify", s.auth(s.handleAuditVerify))
	s.handler = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// auth enforces the bearer token in constant time.
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if s.cfg.Token == "" || len(h) <= len(prefix) ||
			subtle.ConstantTimeCompare([]byte(h[:len(prefix)]), []byte(prefix)) != 1 ||
			subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(s.cfg.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sentinel"`)
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		next(w, r)
	})
}

// CheckRequest describes one authentication attempt to decide.
type CheckRequest struct {
	Account  string `json:"account"`
	IP       string `json:"ip"`
	ClientID string `json:"client_id"` // optional OAuth client
	DeviceID string `json:"device_id"` // optional fingerprint
}

// CheckResponse is the combined decision.
type CheckResponse struct {
	Decision          string   `json:"decision"` // allow | challenge | deny
	Score             int      `json:"score"`
	Reasons           []string `json:"reasons,omitempty"`
	RetryAfterSeconds int64    `json:"retry_after_seconds,omitempty"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Account == "" || req.IP == "" {
		writeError(w, http.StatusBadRequest, "account and ip are required")
		return
	}

	resp := CheckResponse{Decision: "allow"}
	var retryAfter time.Duration

	// 1. Rate limits — every applicable class must pass.
	limits := []struct{ class, key string }{{"ip", req.IP}, {"user", req.Account}}
	if req.ClientID != "" {
		limits = append(limits, struct{ class, key string }{"client", req.ClientID})
	}
	for _, l := range limits {
		d, err := s.cfg.Limiter.Allow(l.class, l.key)
		if err != nil {
			s.internalError(w, "ratelimit", err)
			return
		}
		if !d.Allowed {
			resp.Decision = "deny"
			resp.Reasons = append(resp.Reasons, "rate_limited:"+l.class)
			if d.RetryAfter > retryAfter {
				retryAfter = d.RetryAfter
			}
		}
	}

	// 2. Lockout — evaluated even when already rate-limited so the audit
	// record carries every reason (and work stays uniform across paths).
	if ld := s.cfg.Lockouts.Check(req.Account, req.IP); ld.Locked {
		resp.Decision = "deny"
		resp.Reasons = append(resp.Reasons, "locked_out:"+string(ld.Dimension))
		if ld.RetryAfter > retryAfter {
			retryAfter = ld.RetryAfter
		}
	}

	// 3. Risk — decides only when the hard gates passed.
	as := s.cfg.Risk.Score(risk.Attempt{
		Account: req.Account, IP: req.IP, DeviceID: req.DeviceID, At: s.cfg.Now(),
	})
	resp.Score = as.Score
	for _, reason := range as.Reasons {
		resp.Reasons = append(resp.Reasons, "risk:"+reason.Signal)
	}
	if resp.Decision == "allow" {
		switch as.Action {
		case risk.Deny:
			resp.Decision = "deny"
		case risk.StepUp:
			resp.Decision = "challenge"
		}
	}
	if retryAfter > 0 {
		secs := int64((retryAfter + time.Second - 1) / time.Second)
		resp.RetryAfterSeconds = secs
		w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	}

	if err := s.audit(audit.Event{
		Type:   "sentinel.decision",
		Actor:  req.Account,
		Action: resp.Decision,
		Details: map[string]string{
			"ip":       req.IP,
			"score":    strconv.Itoa(resp.Score),
			"reasons":  strings.Join(resp.Reasons, ","),
			"decision": resp.Decision,
		},
	}); err != nil {
		// Fail closed: without a durable audit record the decision is not
		// authoritative, so we must not return it.
		s.internalError(w, "audit append", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ReportAuthResultRequest feeds an authentication outcome back.
type ReportAuthResultRequest struct {
	Account  string `json:"account"`
	IP       string `json:"ip"`
	DeviceID string `json:"device_id"`
	Success  bool   `json:"success"`
}

func (s *Server) handleReportAuthResult(w http.ResponseWriter, r *http.Request) {
	var req ReportAuthResultRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Account == "" || req.IP == "" {
		writeError(w, http.StatusBadRequest, "account and ip are required")
		return
	}
	if req.Success {
		s.cfg.Lockouts.Success(req.Account, req.IP)
	} else {
		s.cfg.Lockouts.Fail(req.Account, req.IP)
	}
	s.cfg.Risk.Observe(risk.Attempt{
		Account: req.Account, IP: req.IP, DeviceID: req.DeviceID, At: s.cfg.Now(),
	}, req.Success)

	result := "failure"
	if req.Success {
		result = "success"
	}
	if err := s.audit(audit.Event{
		Type:   "auth.result",
		Actor:  req.Account,
		Action: result,
		Details: map[string]string{
			"ip":      req.IP,
			"success": strconv.FormatBool(req.Success),
		},
	}); err != nil {
		s.internalError(w, "audit append", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

// EventRequest is an arbitrary event to append to the audit chain.
type EventRequest struct {
	Type    string            `json:"type"`
	Actor   string            `json:"actor"`
	Action  string            `json:"action"`
	Details map[string]string `json:"details"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	var req EventRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Type == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "type and action are required")
		return
	}
	// Reserved prefixes name sentinel's own internal events; a client must not
	// be able to forge them into the audit chain.
	if strings.HasPrefix(req.Type, "sentinel.") || strings.HasPrefix(req.Type, "auth.") {
		writeError(w, http.StatusBadRequest, "event type uses a reserved prefix (sentinel.*, auth.*)")
		return
	}
	rec, err := s.cfg.Audit.Append(audit.Event(req))
	if err != nil {
		s.internalError(w, "audit append", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"seq": rec.Seq, "hash": rec.Hash})
}

// handleAuditVerify answers with the chain walk *and* the out-of-band anchor
// cross-check. The walk alone cannot see tail-truncation — a prefix of a valid
// chain is itself a valid chain — so this endpoint would otherwise pronounce a
// gutted log intact.
func (s *Server) handleAuditVerify(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Audit.VerifyAll())
}

// audit appends and returns any error: the audit chain IS the compliance
// evidence, so callers fail closed when the write fails rather than return an
// unlogged (and thus non-authoritative) decision.
func (s *Server) audit(e audit.Event) error {
	if _, err := s.cfg.Audit.Append(e); err != nil {
		s.cfg.Logger.Error("audit append failed", "type", e.Type, "err", err)
		return err
	}
	return nil
}

func (s *Server) internalError(w http.ResponseWriter, what string, err error) {
	s.cfg.Logger.Error(what+" failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
