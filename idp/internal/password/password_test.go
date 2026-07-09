package password

import (
	"strings"
	"testing"
)

var fast = Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("correct horse battery staple", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %s", h)
	}
	ok, err := Verify("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatalf("verify legit: ok=%v err=%v", ok, err)
	}
	ok, err = Verify("wrong password", h)
	if err != nil || ok {
		t.Fatalf("verify wrong: ok=%v err=%v", ok, err)
	}
}

func TestHashIsSalted(t *testing.T) {
	h1, _ := Hash("same", fast)
	h2, _ := Hash("same", fast)
	if h1 == h2 {
		t.Fatal("identical hashes for same password — salt not applied")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "notahash", "$argon2id$v=19$m=1024$onlyfourfields",
		"$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA",  // wrong variant
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdA$aGFzaA", // wrong version
		"$argon2id$v=19$m=x,t=1,p=1$c2FsdA$aGFzaA",    // unparseable params
	} {
		if _, err := Verify("x", bad); err != ErrMalformedHash {
			t.Errorf("Verify(%q): err=%v, want ErrMalformedHash", bad, err)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	weak, _ := Hash("pw", Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32})
	if !NeedsRehash(weak, Default) {
		t.Error("weak hash should need rehash against Default")
	}
	strong, _ := Hash("pw", Default)
	if NeedsRehash(strong, Default) {
		t.Error("Default hash should not need rehash against Default")
	}
	if !NeedsRehash("garbage", Default) {
		t.Error("unparseable hash should need rehash")
	}
}
