package audit

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := l.Append(Event{
			Type:    "auth.failure",
			Actor:   "alice",
			Action:  "login",
			Details: map[string]string{"ip": "203.0.113.7"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	l, err := New(NewMemStore(), Options{Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 10)
	recs, _ := l.Records()
	if res := Verify(recs); !res.OK {
		t.Fatalf("expected valid chain, got broken at %d: %s", res.BrokenSeq, res.Reason)
	}
	if err := VerifyErr(recs); err != nil {
		t.Fatal(err)
	}
	if recs[0].Prev != GenesisPrev {
		t.Fatalf("first record prev = %q, want genesis", recs[0].Prev)
	}
}

func TestTamperDetection(t *testing.T) {
	build := func(t *testing.T) []Record {
		l, err := New(NewMemStore(), Options{Now: fixedClock()})
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, l, 5)
		recs, _ := l.Records()
		return recs
	}

	tests := []struct {
		name    string
		mutate  func([]Record) []Record
		wantSeq uint64
		reason  string
	}{
		{
			name: "modified field",
			mutate: func(r []Record) []Record {
				r[2].Actor = "mallory"
				return r
			},
			wantSeq: 3, reason: "recomputation",
		},
		{
			name: "modified detail",
			mutate: func(r []Record) []Record {
				r[1].Details["ip"] = "10.0.0.1"
				return r
			},
			wantSeq: 2, reason: "recomputation",
		},
		{
			name: "deleted record",
			mutate: func(r []Record) []Record {
				return append(r[:2], r[3:]...)
			},
			wantSeq: 4, reason: "sequence gap",
		},
		{
			name: "reordered records",
			mutate: func(r []Record) []Record {
				r[1], r[2] = r[2], r[1]
				return r
			},
			wantSeq: 3, reason: "sequence gap",
		},
		{
			name: "rehashed forgery without fixing successors",
			mutate: func(r []Record) []Record {
				r[2].Actor = "mallory"
				h, err := hashRecord(r[2])
				if err != nil {
					panic(err)
				}
				r[2].Hash = h
				return r
			},
			wantSeq: 4, reason: "prev does not match",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recs := tc.mutate(build(t))
			res := Verify(recs)
			if res.OK {
				t.Fatal("tamper not detected")
			}
			if res.BrokenSeq != tc.wantSeq {
				t.Fatalf("broken at seq %d (%s), want %d", res.BrokenSeq, res.Reason, tc.wantSeq)
			}
			if !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", res.Reason, tc.reason)
			}
		})
	}
}

func TestAnchors(t *testing.T) {
	l, err := New(NewMemStore(), Options{Now: fixedClock(), AnchorEvery: 3})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3)
	recs, _ := l.Records()
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 3 events + 1 anchor", len(recs))
	}
	anchor := recs[3]
	if anchor.Type != AnchorType {
		t.Fatalf("record 4 type = %q, want anchor", anchor.Type)
	}
	if anchor.Details["head_hash"] != recs[2].Hash || anchor.Details["head_seq"] != "3" {
		t.Fatalf("anchor does not checkpoint the chain head: %+v", anchor.Details)
	}
	if res := Verify(recs); !res.OK {
		t.Fatalf("anchored chain broken: %s", res.Reason)
	}
}

func TestFileStoreResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	now := fixedClock()

	s1, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := New(s1, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l1, 3)
	s1.Close()

	// Reopen: the chain must continue, not restart.
	s2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	l2, err := New(s2, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 3)

	recs, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("got %d records, want 6", len(recs))
	}
	if res := Verify(recs); !res.OK {
		t.Fatalf("resumed chain broken at %d: %s", res.BrokenSeq, res.Reason)
	}
}

func TestConcurrentAppend(t *testing.T) {
	l, err := New(NewMemStore(), Options{AnchorEvery: 7})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 50; i++ {
				if _, err := l.Append(Event{Type: "t", Actor: "a", Action: "x"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	recs, _ := l.Records()
	if res := Verify(recs); !res.OK {
		t.Fatalf("chain broken under concurrency at %d: %s", res.BrokenSeq, res.Reason)
	}
}

// TestPythonVerifierAgrees proves the cross-language contract: a chain
// written by this package verifies with the stdlib-Python reimplementation,
// and Python detects tampering in a corrupted copy.
func TestPythonVerifierAgrees(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	script, err := filepath.Abs("../tools/compliance/verify_chain.py")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(s, Options{Now: fixedClock(), AnchorEvery: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i, ev := range []Event{
		{Type: "auth.failure", Actor: "alice", Action: "login", Details: map[string]string{"ip": "203.0.113.7"}},
		{Type: "auth.success", Actor: "bob", Action: "login", Details: map[string]string{"ip": "198.51.100.2", "note": "chars <>&\"\\ and ünïcödé"}},
		{Type: "sentinel.decision", Actor: "sentinel", Action: "deny", Details: map[string]string{"score": "85"}},
		{Type: "auth.failure", Actor: "carol", Action: "login", Details: map[string]string{}},
		{Type: "auth.failure", Actor: "carol", Action: "login"},
	} {
		if _, err := l.Append(ev); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	s.Close()

	out, err := exec.Command(py, script, path).CombinedOutput()
	if err != nil {
		t.Fatalf("python verifier rejected a valid Go-written chain:\n%s", out)
	}

	// Corrupt one record and confirm Python catches it.
	recs, _ := ReadFile(path)
	recs[1].Actor = "mallory"
	bad := filepath.Join(dir, "tampered.jsonl")
	sb, err := OpenFileStore(bad)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := sb.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	sb.Close()
	out, err = exec.Command(py, script, bad).CombinedOutput()
	if err == nil {
		t.Fatalf("python verifier accepted a tampered chain:\n%s", out)
	}
}
