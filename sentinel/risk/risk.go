// Package risk scores authentication attempts 0–100 with a pluggable signal
// pipeline and maps the score to an action: allow, step-up, or deny.
//
// Design:
//
//   - A Signal inspects one attempt plus per-account history and returns
//     points (0 = clean) with a human-readable reason. Signals never mutate
//     history — the Engine records observations only via Observe, on
//     completed attempts, so scoring is a pure function of (attempt,
//     history): deterministic and replayable.
//   - Scores add and clamp to 100. Additive scoring is deliberately dumb:
//     each signal stays independently testable, and the compliance report
//     can attribute a decision to its exact reasons. A trained model is a
//     future Signal, not a rewrite.
//   - Thresholds convert score → action. Defaults: <30 allow, 30–59 step-up
//     (challenge with MFA/CAPTCHA), ≥60 deny.
//
// Built-in signals: impossible travel (haversine distance vs. elapsed time),
// new device fingerprint, attempt velocity, known-bad IP list.
//
// GeoIP seam: signals resolve IP → coordinates through the Geo interface.
// The bundled StaticGeo is a tiny fixture keyed by exact IP, enough for tests
// and demos; production plugs in a MaxMind/GeoIP2 reader behind the same
// method. Unresolvable IPs simply contribute no travel signal — geography
// must fail open, because GeoIP coverage is never complete.
package risk

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// baselineTTL is how long an idle account keeps its device/geo baseline.
// Expiry has to do the ordinary reclamation work so that capacity eviction —
// which destroys exactly the history impossible_travel and new_device need —
// stays the rare last resort rather than the steady state above MaxAccounts.
const baselineTTL = 30 * 24 * time.Hour

// Action is the decision band a score falls into.
type Action string

const (
	Allow  Action = "allow"
	StepUp Action = "step_up"
	Deny   Action = "deny"
)

// Attempt is one authentication attempt to score.
type Attempt struct {
	Account  string
	IP       string
	DeviceID string // opaque device fingerprint; empty = unknown
	At       time.Time
}

// History is what the engine remembers about an account, exposed read-only
// to signals.
type History struct {
	// LastIP/LastSeen/LastLat/LastLon describe the previous observed
	// attempt's location, when resolvable.
	LastIP   string
	LastSeen time.Time
	LastLat  float64
	LastLon  float64
	LastGeo  bool // LastLat/LastLon are valid
	// Devices are fingerprints previously observed for this account.
	Devices map[string]bool
	// Attempts are recent attempt times, newest last (pruned by the engine).
	Attempts []time.Time
}

// Signal scores one aspect of an attempt. Implementations must be
// deterministic and must not retain or mutate hist.
type Signal interface {
	Name() string
	// Score returns 0 when the signal sees nothing suspicious.
	Score(a Attempt, hist History) (points int, reason string)
}

// Geo resolves an IP to coordinates. The production seam for GeoIP2.
type Geo interface {
	Lookup(ip string) (lat, lon float64, ok bool)
}

// StaticGeo is a fixture Geo: exact-IP lookup in a static table.
type StaticGeo map[string][2]float64

func (g StaticGeo) Lookup(ip string) (float64, float64, bool) {
	c, ok := g[ip]
	return c[0], c[1], ok
}

// TestFixture is a small IP→coordinates table used by tests and dev mode.
var TestFixture = StaticGeo{
	"203.0.113.10": {52.52, 13.405},    // Berlin
	"203.0.113.20": {48.8566, 2.3522},  // Paris
	"198.51.100.5": {35.6762, 139.65},  // Tokyo
	"192.0.2.99":   {40.7128, -74.006}, // New York
}

// Thresholds map score bands to actions.
type Thresholds struct {
	StepUp int // score >= StepUp → step_up (default 30)
	Deny   int // score >= Deny → deny (default 60)
}

func (t Thresholds) withDefaults() Thresholds {
	if t.StepUp <= 0 {
		t.StepUp = 30
	}
	if t.Deny <= 0 {
		t.Deny = 60
	}
	return t
}

// Reason attributes points to the signal that assessed them.
type Reason struct {
	Signal string `json:"signal"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// Assessment is the scored outcome of one attempt.
type Assessment struct {
	Score   int      `json:"score"` // 0–100
	Action  Action   `json:"action"`
	Reasons []Reason `json:"reasons"` // only signals that scored > 0
}

// Engine runs signals over per-account history. Safe for concurrent use.
//
// History lives in memory; the state per account is a handful of fields and
// would map to one Redis hash per account (EXPIRE = retention) for a
// multi-instance deployment.
type Engine struct {
	mu         sync.Mutex
	signals    []Signal
	thresholds Thresholds
	geo        Geo
	accounts   map[string]*History
	// retention prunes attempt history older than this (default 1h).
	retention time.Duration
	// maxAccounts bounds the account map (default 50k).
	maxAccounts int
	// evictedBaselines counts histories dropped by the last-resort pass of
	// reclaim — accounts whose device/geo signals are now blind. Non-zero
	// means MaxAccounts is undersized for the user base.
	evictedBaselines uint64
}

// Config assembles an Engine.
type Config struct {
	// Signals run in order; nil selects the default pipeline
	// (impossible travel, new device, velocity, known-bad IP).
	Signals    []Signal
	Thresholds Thresholds
	Geo        Geo // required by the default ImpossibleTravel signal
	// BadIPs seeds the default KnownBadIP signal.
	BadIPs []string
	// Retention bounds per-account attempt history (default 1h).
	Retention time.Duration
	// MaxAccounts bounds how many accounts are tracked at once (default
	// 50000). Account names are attacker-chosen — idp forwards raw login-form
	// usernames — so without a cap a stuffing run walking fresh usernames is
	// an OOM, and sentinel restarting loses every rate-limit window and
	// lockout it holds. Mirrors lockout.Policy.MaxKeys.
	//
	// Sizing rule: in a healthy deployment the steady state is one entry per
	// real user active within baselineTTL, so set this above your active-user
	// count. Below it, eviction starts destroying live device/geo baselines —
	// blinding impossible_travel and new_device for a rotating 10% of
	// accounts. That is logged ("evicted histories with a live device/geo
	// baseline"); a non-zero count means this value is too small.
	MaxAccounts int
}

// New builds an engine. With cfg.Signals nil, the default pipeline is used.
func New(cfg Config) *Engine {
	if cfg.Retention <= 0 {
		cfg.Retention = time.Hour
	}
	if cfg.MaxAccounts <= 0 {
		cfg.MaxAccounts = 50_000
	}
	if cfg.Signals == nil {
		bad := make(map[string]bool, len(cfg.BadIPs))
		for _, ip := range cfg.BadIPs {
			bad[ip] = true
		}
		cfg.Signals = []Signal{
			ImpossibleTravel{Geo: cfg.Geo},
			NewDevice{},
			Velocity{Max: 10, Window: 5 * time.Minute},
			KnownBadIP{Bad: bad},
		}
	}
	return &Engine{
		signals:     cfg.Signals,
		thresholds:  cfg.Thresholds.withDefaults(),
		geo:         cfg.Geo,
		accounts:    make(map[string]*History),
		retention:   cfg.Retention,
		maxAccounts: cfg.MaxAccounts,
	}
}

// Score runs the pipeline over a. It does not record the attempt; pair with
// Observe once the attempt completes.
func (e *Engine) Score(a Attempt) Assessment {
	e.mu.Lock()
	hist := e.snapshot(a.Account, a.At)
	e.mu.Unlock()

	as := Assessment{Action: Allow}
	for _, s := range e.signals {
		pts, detail := s.Score(a, hist)
		if pts <= 0 {
			continue
		}
		as.Score += pts
		as.Reasons = append(as.Reasons, Reason{Signal: s.Name(), Points: pts, Detail: detail})
	}
	if as.Score > 100 {
		as.Score = 100
	}
	switch {
	case as.Score >= e.thresholds.Deny:
		as.Action = Deny
	case as.Score >= e.thresholds.StepUp:
		as.Action = StepUp
	}
	return as
}

// Observe records a completed attempt into history. Call it for every
// attempt (velocity needs failures too); device fingerprints are only
// trusted — added to the known set — on success, otherwise an attacker
// enrolls their device by failing a login.
func (e *Engine) Observe(a Attempt, success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h, ok := e.accounts[a.Account]
	if !ok {
		e.reclaim(a.At)
		h = &History{Devices: make(map[string]bool)}
		e.accounts[a.Account] = h
	}
	h.Attempts = append(h.Attempts, a.At)
	e.prune(h, a.At)
	if !success {
		return
	}
	if a.DeviceID != "" {
		h.Devices[a.DeviceID] = true
	}
	h.LastIP = a.IP
	h.LastSeen = a.At
	h.LastGeo = false
	if e.geo != nil {
		if lat, lon, ok := e.geo.Lookup(a.IP); ok {
			h.LastLat, h.LastLon, h.LastGeo = lat, lon, true
		}
	}
}

// snapshot copies account history for lock-free signal evaluation.
// Caller holds e.mu.
func (e *Engine) snapshot(account string, now time.Time) History {
	h, ok := e.accounts[account]
	if !ok {
		return History{}
	}
	e.prune(h, now)
	out := *h
	out.Devices = make(map[string]bool, len(h.Devices))
	for k := range h.Devices {
		out.Devices[k] = true
	}
	out.Attempts = append([]time.Time(nil), h.Attempts...)
	return out
}

// reclaim bounds the account map before a new key is inserted. Caller holds e.mu.
//
// Triggering on size rather than elapsed time is the point: a stuffing run
// walks a fresh username per attempt, so every entry is young and a time-based
// sweep reclaims nothing until the burst is long over. Histories with nothing
// left in the retention window go first, then those that never saw a
// successful login — those are bare failure counters, then baselines idle
// past baselineTTL. A live baseline is what the signals actually need, so it
// goes last, and only because an unbounded map is the worse failure — and it
// is counted and logged, because a decision made blind must not look like a
// decision made clean.
//
// Reclaiming to a low-water mark rather than to one free slot amortizes the
// O(n) scan over the headroom it frees, as in lockout.reclaim.
func (e *Engine) reclaim(now time.Time) {
	if len(e.accounts) < e.maxAccounts {
		return
	}
	lowWater := e.maxAccounts - e.maxAccounts/10
	passes := []func(*History) bool{
		func(h *History) bool { e.prune(h, now); return len(h.Attempts) == 0 && h.LastSeen.IsZero() },
		func(h *History) bool { return h.LastSeen.IsZero() },
		func(h *History) bool { return !h.LastSeen.IsZero() && now.Sub(h.LastSeen) > baselineTTL },
		func(*History) bool { return true },
	}
	lost := 0
done:
	for i, pass := range passes {
		for k, h := range e.accounts {
			if len(e.accounts) <= lowWater {
				break done
			}
			if pass(h) {
				delete(e.accounts, k)
				if i == len(passes)-1 {
					lost++
				}
			}
		}
	}
	if lost > 0 {
		e.evictedBaselines += uint64(lost)
		slog.Warn("risk: account map at capacity, evicted histories with a live device/geo baseline",
			"evicted", lost, "total", e.evictedBaselines, "max_accounts", e.maxAccounts)
	}
}

// prune drops attempts outside the retention window. Caller holds e.mu.
func (e *Engine) prune(h *History, now time.Time) {
	cut := sort.Search(len(h.Attempts), func(i int) bool {
		return now.Sub(h.Attempts[i]) <= e.retention
	})
	if cut > 0 {
		h.Attempts = append(h.Attempts[:0], h.Attempts[cut:]...)
	}
}

// ---- Built-in signals ----

// ImpossibleTravel flags logins whose implied speed from the last observed
// location exceeds MaxKMH.
type ImpossibleTravel struct {
	Geo    Geo
	Points int     // default 45
	MaxKMH float64 // default 900 (fast commercial flight)
}

func (ImpossibleTravel) Name() string { return "impossible_travel" }

func (s ImpossibleTravel) Score(a Attempt, hist History) (int, string) {
	if s.Geo == nil || !hist.LastGeo || a.IP == hist.LastIP {
		return 0, ""
	}
	lat, lon, ok := s.Geo.Lookup(a.IP)
	if !ok {
		return 0, "" // no coverage: fail open (see package doc)
	}
	km := haversineKM(hist.LastLat, hist.LastLon, lat, lon)
	elapsed := a.At.Sub(hist.LastSeen)
	if elapsed <= 0 {
		elapsed = time.Second
	}
	maxKMH := s.MaxKMH
	if maxKMH == 0 {
		maxKMH = 900
	}
	speed := km / elapsed.Hours()
	if speed <= maxKMH {
		return 0, ""
	}
	pts := s.Points
	if pts == 0 {
		pts = 45
	}
	return pts, fmtKMH(km, speed)
}

// NewDevice flags a fingerprint never observed for the account. An empty
// fingerprint scores too — "no fingerprint" is at least as suspicious as an
// unknown one.
type NewDevice struct {
	Points int // default 20
}

func (NewDevice) Name() string { return "new_device" }

func (s NewDevice) Score(a Attempt, hist History) (int, string) {
	if a.DeviceID != "" && hist.Devices[a.DeviceID] {
		return 0, ""
	}
	if len(hist.Devices) == 0 && a.DeviceID != "" {
		// First-ever device for the account: enrollment, not anomaly.
		return 0, ""
	}
	pts := s.Points
	if pts == 0 {
		pts = 20
	}
	if a.DeviceID == "" {
		return pts, "no device fingerprint presented"
	}
	return pts, "device fingerprint not previously seen for account"
}

// Velocity flags more than Max attempts inside Window for the account.
type Velocity struct {
	Max    int           // default 10
	Window time.Duration // default 5m
	Points int           // default 25
}

func (Velocity) Name() string { return "velocity" }

func (s Velocity) Score(a Attempt, hist History) (int, string) {
	maxN, win := s.Max, s.Window
	if maxN == 0 {
		maxN = 10
	}
	if win == 0 {
		win = 5 * time.Minute
	}
	n := 0
	for _, t := range hist.Attempts {
		if a.At.Sub(t) <= win {
			n++
		}
	}
	if n < maxN {
		return 0, ""
	}
	pts := s.Points
	if pts == 0 {
		pts = 25
	}
	return pts, fmtVelocity(n, win)
}

// KnownBadIP flags IPs on a blocklist (threat intel feed, tor exits, …).
type KnownBadIP struct {
	Bad    map[string]bool
	Points int // default 60 (deny on its own by default thresholds)
}

func (KnownBadIP) Name() string { return "known_bad_ip" }

func (s KnownBadIP) Score(a Attempt, _ History) (int, string) {
	if !s.Bad[a.IP] {
		return 0, ""
	}
	pts := s.Points
	if pts == 0 {
		pts = 60
	}
	return pts, "ip on known-bad list"
}

func fmtKMH(km, speed float64) string {
	return fmt.Sprintf("%.0f km from last location implies %.0f km/h", km, speed)
}

func fmtVelocity(n int, win time.Duration) string {
	return fmt.Sprintf("%d attempts in %s", n, win)
}

// haversineKM is the great-circle distance between two points in km.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371 // earth radius, km
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := rad(lat2 - lat1)
	dLon := rad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}
