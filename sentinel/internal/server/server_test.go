package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/sentinel/audit"
	"github.com/aikazzh/portfolio/sentinel/lockout"
	"github.com/aikazzh/portfolio/sentinel/ratelimit"
	"github.com/aikazzh/portfolio/sentinel/risk"
)

const testToken = "test-token"

type env struct {
	srv   *Server
	log   *audit.Log
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{clock: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
	now := func() time.Time { return e.clock }

	lim, err := ratelimit.New(ratelimit.NewMemStore(), map[string]ratelimit.Policy{
		"ip":     {Limit: 20, Window: time.Minute},
		"user":   {Limit: 10, Window: time.Minute},
		"client": {Limit: 50, Window: time.Minute},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.NewMemStore(), audit.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	e.log = log
	e.srv = New(Config{
		Token:    testToken,
		Limiter:  lim,
		Lockouts: lockout.New(lockout.Policy{}, now),
		Risk:     risk.New(risk.Config{Geo: risk.TestFixture, BadIPs: []string{"233.252.0.66"}}),
		Audit:    log,
		Now:      now,
	})
	return e
}

func (e *env) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func (e *env) check(t *testing.T, body string) (CheckResponse, *httptest.ResponseRecorder) {
	t.Helper()
	w := e.do(t, "POST", "/v1/check", testToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("check: status %d: %s", w.Code, w.Body)
	}
	var resp CheckResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp, w
}

func TestHealthzNeedsNoAuth(t *testing.T) {
	e := newEnv(t)
	if w := e.do(t, "GET", "/healthz", "", ""); w.Code != http.StatusOK {
		t.Fatalf("healthz: %d", w.Code)
	}
}

func TestBearerAuthRequired(t *testing.T) {
	e := newEnv(t)
	for _, token := range []string{"", "wrong", testToken + "x", strings.ToUpper(testToken)} {
		w := e.do(t, "POST", "/v1/check", token, `{"account":"a","ip":"1.1.1.1"}`)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, want 401", token, w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("missing WWW-Authenticate")
		}
	}
}

func TestCheckAllowsCleanAttempt(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.check(t, `{"account":"alice","ip":"203.0.113.10","device_id":"d1"}`)
	if resp.Decision != "allow" {
		t.Fatalf("decision = %s (%+v)", resp.Decision, resp)
	}
}

func TestCheckDeniesWhenRateLimited(t *testing.T) {
	e := newEnv(t)
	var resp CheckResponse
	var w *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		resp, w = e.check(t, `{"account":"alice","ip":"203.0.113.10"}`)
	}
	if resp.Decision != "deny" || !hasPrefix(resp.Reasons, "rate_limited:user") {
		t.Fatalf("after 12 checks: %+v", resp)
	}
	if resp.RetryAfterSeconds <= 0 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("missing Retry-After: %+v", resp)
	}
}

func TestCheckDeniesWhenLockedOut(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		w := e.do(t, "POST", "/v1/report-auth-result", testToken,
			`{"account":"bob","ip":"203.0.113.20","success":false}`)
		if w.Code != http.StatusOK {
			t.Fatalf("report: %d %s", w.Code, w.Body)
		}
	}
	resp, _ := e.check(t, `{"account":"bob","ip":"203.0.113.20"}`)
	if resp.Decision != "deny" || !hasPrefix(resp.Reasons, "locked_out:") {
		t.Fatalf("locked account: %+v", resp)
	}
	if resp.RetryAfterSeconds <= 0 {
		t.Fatalf("lockout without Retry-After: %+v", resp)
	}
}

func TestCheckDeniesKnownBadIP(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.check(t, `{"account":"alice","ip":"233.252.0.66"}`)
	if resp.Decision != "deny" || !hasPrefix(resp.Reasons, "risk:known_bad_ip") {
		t.Fatalf("bad ip: %+v", resp)
	}
}

func TestCheckChallengesOnImpossibleTravel(t *testing.T) {
	e := newEnv(t)
	// Establish Berlin at t0 via a successful auth result.
	e.do(t, "POST", "/v1/report-auth-result", testToken,
		`{"account":"carol","ip":"203.0.113.10","device_id":"d1","success":true}`)
	e.clock = e.clock.Add(10 * time.Minute)
	// Tokyo 10 minutes later, known device: travel alone → step-up.
	resp, _ := e.check(t, `{"account":"carol","ip":"198.51.100.5","device_id":"d1"}`)
	if resp.Decision != "challenge" || !hasPrefix(resp.Reasons, "risk:impossible_travel") {
		t.Fatalf("travel: %+v", resp)
	}
}

func TestSuccessResetsLockoutCounters(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 4; i++ {
		e.do(t, "POST", "/v1/report-auth-result", testToken,
			`{"account":"dave","ip":"203.0.113.20","success":false}`)
	}
	e.do(t, "POST", "/v1/report-auth-result", testToken,
		`{"account":"dave","ip":"203.0.113.20","success":true}`)
	for i := 0; i < 4; i++ {
		e.do(t, "POST", "/v1/report-auth-result", testToken,
			`{"account":"dave","ip":"203.0.113.20","success":false}`)
	}
	resp, _ := e.check(t, `{"account":"dave","ip":"203.0.113.20"}`)
	if resp.Decision == "deny" {
		t.Fatalf("counters not reset by success: %+v", resp)
	}
}

func TestEventsAppendAndVerify(t *testing.T) {
	e := newEnv(t)
	w := e.do(t, "POST", "/v1/events", testToken,
		`{"type":"admin.change","actor":"root","action":"policy_update","details":{"policy":"ip"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("events: %d %s", w.Code, w.Body)
	}
	var rec struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 1 || len(rec.Hash) != 64 {
		t.Fatalf("bad record ref: %+v", rec)
	}

	w = e.do(t, "GET", "/v1/audit/verify", testToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	var vr audit.VerifyResult
	if err := json.Unmarshal(w.Body.Bytes(), &vr); err != nil {
		t.Fatal(err)
	}
	if !vr.OK || vr.Records != 1 {
		t.Fatalf("verify result: %+v", vr)
	}
}

func TestDecisionsAreAudited(t *testing.T) {
	e := newEnv(t)
	e.check(t, `{"account":"alice","ip":"203.0.113.10"}`)
	e.do(t, "POST", "/v1/report-auth-result", testToken,
		`{"account":"alice","ip":"203.0.113.10","success":false}`)
	recs, err := e.log.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Type != "sentinel.decision" || recs[1].Type != "auth.result" {
		t.Fatalf("audit trail: %+v", recs)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ path, body string }{
		{"/v1/check", `{"ip":"1.1.1.1"}`},
		{"/v1/check", `not json`},
		{"/v1/check", `{"account":"a","ip":"1.1.1.1","surprise":true}`},
		{"/v1/report-auth-result", `{"account":"a"}`},
		{"/v1/events", `{"actor":"x"}`},
	}
	for _, tc := range cases {
		w := e.do(t, "POST", tc.path, testToken, tc.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: status %d, want 400", tc.path, tc.body, w.Code)
		}
	}
}

func TestUnknownClientClassStillChecksClient(t *testing.T) {
	e := newEnv(t)
	// Exhaust the client class (limit 50) to prove client_id participates.
	for i := 0; i < 51; i++ {
		e.do(t, "POST", "/v1/check", testToken,
			fmt.Sprintf(`{"account":"u%d","ip":"10.0.0.%d","client_id":"app"}`, i, i%250+1))
	}
	resp, _ := e.check(t, `{"account":"fresh","ip":"10.0.250.1","client_id":"app"}`)
	if resp.Decision != "deny" || !hasPrefix(resp.Reasons, "rate_limited:client") {
		t.Fatalf("client limit: %+v", resp)
	}
}

func TestEventsRejectReservedTypes(t *testing.T) {
	e := newEnv(t)
	for _, typ := range []string{"sentinel.decision", "auth.result", "sentinel.anchor"} {
		body := fmt.Sprintf(`{"type":%q,"actor":"eve","action":"forge"}`, typ)
		w := e.do(t, "POST", "/v1/events", testToken, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("type %q: status %d, want 400", typ, w.Code)
		}
	}
	// Confirm no forged record slipped into the chain.
	if recs, _ := e.log.Records(); len(recs) != 0 {
		t.Fatalf("reserved events were appended: %+v", recs)
	}
}

// failStore fails every append, simulating a dead audit backend.
type failStore struct{}

func (failStore) Append(audit.Record) error         { return fmt.Errorf("disk full") }
func (failStore) Records() ([]audit.Record, error)  { return nil, nil }
func (failStore) Last() (audit.Record, bool, error) { return audit.Record{}, false, nil }

func TestCheckFailsClosedWhenAuditFails(t *testing.T) {
	e := newEnv(t)
	log, err := audit.New(failStore{}, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Audit = log // swap in the failing log
	w := e.do(t, "POST", "/v1/check", testToken, `{"account":"alice","ip":"203.0.113.10"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("check with failing audit: status %d, want 500 (fail closed)", w.Code)
	}
}

func hasPrefix(ss []string, prefix string) bool {
	for _, s := range ss {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
