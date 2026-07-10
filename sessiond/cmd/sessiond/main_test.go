package main

import (
	"os"
	"strings"
	"testing"
)

// TestDemoNotGatedByEnv is a regression guard for SESS-P2: demo routes mint
// unauthenticated real sessions, so they must be reachable only when we are
// both in dev mode AND backed by the throwaway embedded store. devMode alone is
// insufficient: SESSIOND_DEV_MODE=1 with an explicit SESSIOND_REDIS_URL skips
// miniredis and would otherwise expose demo minting against prod Redis. run()
// isn't unit-testable without a live listener, so this pins the source.
func TestDemoNotGatedByEnv(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `os.Getenv("SESSIOND_DEMO")`) {
		t.Fatal("EnableDemo must not be gated by a SESSIOND_DEMO env escape hatch")
	}
	if !strings.Contains(string(src), "EnableDemo: devMode && embedded") {
		t.Fatal("EnableDemo must require devMode AND the embedded store, not devMode alone")
	}
}
