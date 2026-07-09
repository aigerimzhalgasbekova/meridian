// Package audit implements a hash-chained, append-only audit log.
//
// Each record embeds SHA-256(prev record hash || canonical JSON of the
// record's event fields), so any modification, deletion, or reordering of a
// past record breaks every subsequent hash. Verify walks the chain and
// reports the first broken link.
//
// Canonical form (cross-language by design — reimplemented in
// tools/compliance/verify_chain.py):
//   - compact JSON, keys sorted lexicographically, HTML escaping disabled
//   - all fields always present (no omitempty ambiguity)
//   - details values are strings only — no float/number formatting ambiguity
//   - hash input = ASCII hex of prev hash ++ canonical JSON bytes
//
// Anchoring: every AnchorEvery records the log appends an anchor record whose
// details capture the current chain head (seq + hash). Anchors are themselves
// chained. In production the anchor hash would additionally be pushed to an
// external notary the log operator cannot rewrite — e.g. KMS-signed and
// written to a WORM S3 object-lock bucket, or submitted to a timestamping
// authority (RFC 3161). Verifiers then only need one trusted anchor to prove
// everything before it; without an external anchor, a chain is only
// tamper-evident against attackers who cannot rewrite the whole file.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// GenesisPrev is the prev value of the first record: 64 hex zeros.
const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// AnchorType is the record type of periodic chain-head checkpoints.
const AnchorType = "sentinel.anchor"

// Event is what callers append: everything except chain bookkeeping.
type Event struct {
	Type    string            // e.g. "auth.failure", "sentinel.decision"
	Actor   string            // who acted (user ID, service name)
	Action  string            // what happened
	Details map[string]string // free-form context; string values only (canonical form)
}

// Record is a chained event as stored.
type Record struct {
	Seq     uint64            `json:"seq"`
	TS      string            `json:"ts"` // RFC3339Nano, UTC
	Type    string            `json:"type"`
	Actor   string            `json:"actor"`
	Action  string            `json:"action"`
	Details map[string]string `json:"details"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
}

// Store persists records in append order.
//
// Records loads the full chain into memory; fine for a service-lifetime log,
// and the seam where a Postgres-backed store with streaming verification
// would slot in (SELECT ... ORDER BY seq, verify incrementally).
type Store interface {
	Append(Record) error
	Records() ([]Record, error)
	// Last returns the most recent record, or ok=false for an empty store.
	Last() (rec Record, ok bool, err error)
}

// canonical returns the canonical JSON of a record with the hash field
// excluded: compact, sorted keys, no HTML escaping.
func canonical(r Record) ([]byte, error) {
	if r.Details == nil {
		r.Details = map[string]string{}
	}
	// Marshal via map: encoding/json sorts map keys, giving the
	// lexicographic key order the Python verifier reproduces with
	// sort_keys=True.
	m := map[string]any{
		"seq":     r.Seq,
		"ts":      r.TS,
		"type":    r.Type,
		"actor":   r.Actor,
		"action":  r.Action,
		"details": r.Details,
		"prev":    r.Prev,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// hashRecord computes hex(SHA-256(prev hash hex || canonical JSON)).
func hashRecord(r Record) (string, error) {
	c, err := canonical(r)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(r.Prev))
	h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Log is a hash-chained audit log over a Store. Safe for concurrent use.
type Log struct {
	mu          sync.Mutex
	store       Store
	now         func() time.Time
	anchorEvery uint64
	// chain head, cached to avoid re-reading the store per append
	lastSeq  uint64
	lastHash string
	empty    bool
}

// Options configure a Log.
type Options struct {
	// AnchorEvery appends an anchor record after every N ordinary records.
	// 0 disables anchoring.
	AnchorEvery uint64
	// Now supplies the clock; defaults to time.Now.
	Now func() time.Time
}

// New opens a log over store, resuming the chain from the store's last
// record if it is non-empty.
func New(store Store, opts Options) (*Log, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Log{store: store, now: opts.Now, anchorEvery: opts.AnchorEvery, empty: true, lastHash: GenesisPrev}
	last, ok, err := store.Last()
	if err != nil {
		return nil, fmt.Errorf("audit: reading chain head: %w", err)
	}
	if ok {
		l.empty = false
		l.lastSeq = last.Seq
		l.lastHash = last.Hash
	}
	return l, nil
}

// Append chains and persists an event, returning the stored record.
func (l *Log) Append(e Event) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, err := l.append(e)
	if err != nil {
		return Record{}, err
	}
	if l.anchorEvery > 0 && rec.Seq%l.anchorEvery == 0 {
		// The anchor checkpoints the head we just wrote; in production its
		// hash would also go to the external notary (see package doc).
		if _, err := l.append(Event{
			Type:   AnchorType,
			Actor:  "sentinel",
			Action: "anchor",
			Details: map[string]string{
				"head_seq":  strconv.FormatUint(rec.Seq, 10),
				"head_hash": rec.Hash,
			},
		}); err != nil {
			return rec, fmt.Errorf("audit: appending anchor: %w", err)
		}
	}
	return rec, nil
}

func (l *Log) append(e Event) (Record, error) {
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	rec := Record{
		Seq:     l.lastSeq + 1,
		TS:      l.now().UTC().Format(time.RFC3339Nano),
		Type:    e.Type,
		Actor:   e.Actor,
		Action:  e.Action,
		Details: e.Details,
		Prev:    l.lastHash,
	}
	if l.empty {
		rec.Seq = 1
	}
	h, err := hashRecord(rec)
	if err != nil {
		return Record{}, err
	}
	rec.Hash = h
	if err := l.store.Append(rec); err != nil {
		return Record{}, fmt.Errorf("audit: append: %w", err)
	}
	l.empty = false
	l.lastSeq = rec.Seq
	l.lastHash = rec.Hash
	return rec, nil
}

// Records returns the full chain.
func (l *Log) Records() ([]Record, error) { return l.store.Records() }

// ErrChainBroken is wrapped by every verification failure.
var ErrChainBroken = errors.New("audit: chain broken")

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	OK      bool `json:"ok"`
	Records int  `json:"records"`
	// BrokenSeq and Reason identify the first broken link when !OK.
	BrokenSeq uint64 `json:"broken_seq,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Verify walks records in order and reports the first broken link: a seq
// gap, a prev that does not match the previous record's hash, or a stored
// hash that does not match recomputation.
func Verify(records []Record) VerifyResult {
	res := VerifyResult{OK: true, Records: len(records)}
	prevHash := GenesisPrev
	var prevSeq uint64
	for i, r := range records {
		fail := func(reason string) VerifyResult {
			return VerifyResult{Records: len(records), BrokenSeq: r.Seq, Reason: reason}
		}
		if i == 0 {
			prevSeq = r.Seq - 1
		}
		if r.Seq != prevSeq+1 {
			return fail(fmt.Sprintf("sequence gap: expected %d, got %d", prevSeq+1, r.Seq))
		}
		if r.Prev != prevHash {
			return fail("prev does not match previous record hash")
		}
		want, err := hashRecord(r)
		if err != nil {
			return fail("unhashable record: " + err.Error())
		}
		if want != r.Hash {
			return fail("stored hash does not match recomputation")
		}
		prevSeq, prevHash = r.Seq, r.Hash
	}
	return res
}

// VerifyErr is Verify with an error shape for callers that want errors.Is.
func VerifyErr(records []Record) error {
	if res := Verify(records); !res.OK {
		return fmt.Errorf("%w at seq %d: %s", ErrChainBroken, res.BrokenSeq, res.Reason)
	}
	return nil
}
