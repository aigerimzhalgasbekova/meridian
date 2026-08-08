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
	"io"
	"strconv"
	"strings"
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

// validUTF8 replaces invalid UTF-8 bytes with U+FFFD, making hashRecord a
// function of the record alone (see Log.append).
func validUTF8(s string) string { return strings.ToValidUTF8(s, "�") }

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
	anchorSink  io.Writer // out-of-band anchor sidecar; nil disables it
	// anchorSource reopens that sidecar for reading, so VerifyAll can do the
	// truncation cross-check the chain walk cannot.
	anchorSource func() (io.ReadCloser, error)
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
	// AnchorSink, if set, receives each anchor (chain head seq+hash+ts) as a
	// JSON line in a separate append-only file. Living out-of-band gives
	// truncation resistance the in-file anchors cannot: tail-truncating the
	// main log leaves the sidecar's last anchor pointing past the new head, so
	// verify_chain.py detects the loss.
	AnchorSink io.Writer
	// AnchorSource opens the same sidecar for reading. Required for
	// VerifyExport to do the cross-check — without it a truncated log looks
	// intact, because a prefix of a valid chain is itself a valid chain.
	AnchorSource func() (io.ReadCloser, error)
	// Now supplies the clock; defaults to time.Now.
	Now func() time.Time
}

// Anchor is one line of the out-of-band sidecar: a checkpointed chain head.
type Anchor struct {
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	TS       string `json:"ts"`
}

// ReadAnchors parses the JSONL anchor sidecar.
func ReadAnchors(r io.Reader) ([]Anchor, error) {
	var out []Anchor
	dec := json.NewDecoder(r)
	for {
		var a Anchor
		if err := dec.Decode(&a); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("audit: reading anchor sidecar: %w", err)
		}
		out = append(out, a)
	}
}

// New opens a log over store, resuming the chain from the store's last
// record if it is non-empty.
func New(store Store, opts Options) (*Log, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Log{
		store: store, now: opts.Now, anchorEvery: opts.AnchorEvery,
		anchorSink: opts.AnchorSink, anchorSource: opts.AnchorSource,
		empty: true, lastHash: GenesisPrev,
	}
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
	// Anchor the first record as well as every Nth: until an anchor exists the
	// sidecar is empty, and an empty sidecar is indistinguishable from a
	// deleted one — VerifyExport would call a healthy young log tampered, and
	// a log truncated below the first anchor untampered.
	if l.anchorEvery > 0 && (rec.Seq == 1 || rec.Seq%l.anchorEvery == 0) {
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
		if err := l.writeAnchor(rec); err != nil {
			return rec, fmt.Errorf("audit: writing anchor sidecar: %w", err)
		}
	}
	return rec, nil
}

// writeAnchor durably records the checkpointed chain head to the out-of-band
// sidecar (if configured), so truncation of the main log is detectable.
func (l *Log) writeAnchor(head Record) error {
	if l.anchorSink == nil {
		return nil
	}
	line, err := json.Marshal(map[string]any{
		"head_seq":  head.Seq,
		"head_hash": head.Hash,
		"ts":        head.TS,
	})
	if err != nil {
		return err
	}
	if _, err := l.anchorSink.Write(append(line, '\n')); err != nil {
		return err
	}
	// Sidecar durability matters as much as the chain's; fsync if we can.
	if sync, ok := l.anchorSink.(interface{ Sync() error }); ok {
		return sync.Sync()
	}
	return nil
}

func (l *Log) append(e Event) (Record, error) {
	// encoding/json escapes an invalid UTF-8 byte as � but writes a real
	// U+FFFD raw, so a record containing one hashes differently before and
	// after the store's JSON round-trip — it would verify as BROKEN forever,
	// indistinguishable from tampering. Coerce rather than reject: the chain's
	// job is to record what happened, not to refuse it.
	details := make(map[string]string, len(e.Details))
	for k, v := range e.Details { // fresh map: Append does not own the caller's
		details[validUTF8(k)] = validUTF8(v)
	}
	rec := Record{
		Seq:     l.lastSeq + 1,
		TS:      l.now().UTC().Format(time.RFC3339Nano),
		Type:    validUTF8(e.Type),
		Actor:   validUTF8(e.Actor),
		Action:  validUTF8(e.Action),
		Details: details,
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
	// UnvouchedRecords is how many records sit past the last out-of-band
	// anchor. No anchor vouches for them, so they can be deleted or
	// fabricated without either verifier noticing — "OK" means "intact up to
	// the last anchor". Normally 0..AnchorEvery-1; a large number means the
	// sidecar has stopped being written.
	UnvouchedRecords int `json:"unvouched_records,omitempty"`
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

// VerifyExport is the only honest answer to "is this log intact": the chain
// walk *and* the out-of-band anchor cross-check. A prefix of a valid chain is
// itself a valid chain, so Verify alone cannot see tail-truncation — only the
// sidecar can, because it lives in a separate file the truncation did not
// touch. This mirrors verify_chain.py's verify_export; any entry point that
// pronounces on integrity must call this, never Verify on its own.
//
// What this covers: truncating or rewriting the log alone, and deleting or
// emptying the sidecar (both fail closed — every non-empty log is anchored
// from its first record). What it does not cover: an attacker who edits *both*
// files, since the sidecar sits beside the log with the same owner and mode —
// trimming the anchors to match a truncated log still verifies. Nor does it
// see the last (AnchorEvery-1) records, which no anchor vouches for yet: those
// can be deleted, and arbitrary records appended in their place, and both
// verifiers still say OK. That window is reported as UnvouchedRecords rather
// than left silent — "OK" means "intact up to the last anchor".
// ponytail: closing that needs the sidecar somewhere this service cannot
// rewrite (object-locked S3 or a separate writer identity), which is what the
// package doc's "external notary" means.
func VerifyExport(records []Record, anchors []Anchor, anchorErr error) VerifyResult {
	res := Verify(records)
	if !res.OK {
		return res
	}
	if anchorErr != nil {
		return VerifyResult{Records: len(records), Reason: "anchor sidecar unreadable: " + anchorErr.Error()}
	}
	if len(records) == 0 && len(anchors) == 0 {
		return res // nothing logged yet, so nothing to vouch for
	}
	if len(anchors) == 0 {
		return VerifyResult{Records: len(records), Reason: "anchor sidecar is empty (deleted or truncated?)"}
	}
	last := anchors[len(anchors)-1]
	for _, r := range records {
		if r.Seq != last.HeadSeq {
			continue
		}
		if r.Hash != last.HeadHash {
			return VerifyResult{Records: len(records), BrokenSeq: r.Seq, Reason: "anchor hash mismatch"}
		}
		// Report the size of the blind spot rather than leaving it silent:
		// everything past the last anchor is chain-consistent but unvouched.
		for _, r := range records {
			if r.Seq > last.HeadSeq {
				res.UnvouchedRecords++
			}
		}
		return res
	}
	return VerifyResult{
		Records:   len(records),
		BrokenSeq: last.HeadSeq,
		Reason:    "anchor vouches for a seq absent from the log (truncated?)",
	}
}

// VerifyAll is VerifyExport over the log's own records and sidecar.
func (l *Log) VerifyAll() VerifyResult {
	recs, err := l.store.Records()
	if err != nil {
		return VerifyResult{Reason: "audit read failed: " + err.Error()}
	}
	if l.anchorSource == nil {
		// No sidecar configured (memory store, tests): the chain walk is all
		// there is, and it cannot see tail-truncation. Say so rather than
		// claiming more than we checked.
		return Verify(recs)
	}
	rc, err := l.anchorSource()
	if err != nil {
		return VerifyExport(recs, nil, err)
	}
	defer rc.Close()
	anchors, err := ReadAnchors(rc)
	return VerifyExport(recs, anchors, err)
}

// VerifyErr is Verify with an error shape for callers that want errors.Is.
func VerifyErr(records []Record) error {
	if res := Verify(records); !res.OK {
		return fmt.Errorf("%w at seq %d: %s", ErrChainBroken, res.BrokenSeq, res.Reason)
	}
	return nil
}
