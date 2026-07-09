package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func newEdKey(t *testing.T, id string) (SigningKey, VerificationKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKey{ID: id, Alg: AlgEdDSA, Private: priv},
		VerificationKey{ID: id, Alg: AlgEdDSA, Public: pub}
}

func newECKey(t *testing.T, id string) (SigningKey, VerificationKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKey{ID: id, Alg: AlgES256, Private: priv},
		VerificationKey{ID: id, Alg: AlgES256, Public: &priv.PublicKey}
}

var testRSA *rsa.PrivateKey // generated once; RSA keygen is slow

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if testRSA == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		testRSA = k
	}
	return testRSA
}

func newRSAKey(t *testing.T, id string) (SigningKey, VerificationKey) {
	t.Helper()
	priv := rsaKey(t)
	return SigningKey{ID: id, Alg: AlgRS256, Private: priv},
		VerificationKey{ID: id, Alg: AlgRS256, Public: &priv.PublicKey}
}

func resolverFor(t *testing.T, keys ...VerificationKey) KeyResolver {
	t.Helper()
	set, err := NewKeySet(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestSignVerifyRoundTrip(t *testing.T) {
	payload := []byte(`{"sub":"alice"}`)
	cases := []struct {
		name string
		mk   func(t *testing.T, id string) (SigningKey, VerificationKey)
	}{
		{"EdDSA", newEdKey},
		{"ES256", newECKey},
		{"RS256", newRSAKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sk, vk := tc.mk(t, "k1")
			token, err := Sign(payload, sk)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, hdr, err := Verify(token, resolverFor(t, vk), []Algorithm{sk.Alg})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if string(got) != string(payload) {
				t.Errorf("payload mismatch: %q", got)
			}
			if hdr.Kid != "k1" || hdr.Typ != "JWT" {
				t.Errorf("unexpected header: %+v", hdr)
			}
		})
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	sk, vk := newEdKey(t, "k1")
	token, err := Sign([]byte(`{"sub":"alice"}`), sk)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	t.Run("modified payload", func(t *testing.T) {
		forged := parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"mallory"}`)) + "." + parts[2]
		if _, _, err := Verify(forged, resolverFor(t, vk), []Algorithm{AlgEdDSA}); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("want ErrSignatureInvalid, got %v", err)
		}
	})
	t.Run("truncated signature", func(t *testing.T) {
		forged := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4]
		if _, _, err := Verify(forged, resolverFor(t, vk), []Algorithm{AlgEdDSA}); err == nil {
			t.Error("truncated signature accepted")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		_, other := newEdKey(t, "k1") // same kid, different key material
		if _, _, err := Verify(token, resolverFor(t, other), []Algorithm{AlgEdDSA}); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("want ErrSignatureInvalid, got %v", err)
		}
	})
}

// forgeToken builds a token with an arbitrary header, signed or not.
func forgeToken(t *testing.T, hdr map[string]any, payload []byte, sig []byte) string {
	t.Helper()
	rawHdr, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	tok := b64.EncodeToString(rawHdr) + "." + b64.EncodeToString(payload) + "."
	if sig != nil {
		tok += b64.EncodeToString(sig)
	}
	return tok
}

// TestKnownAttackPatterns exercises the vulnerability classes that have hit
// real JOSE implementations. Every one must fail closed.
func TestKnownAttackPatterns(t *testing.T) {
	skEd, vkEd := newEdKey(t, "ed-1")
	payload := []byte(`{"sub":"alice","admin":true}`)
	genuine, err := Sign(payload, skEd)
	if err != nil {
		t.Fatal(err)
	}
	resolver := resolverFor(t, vkEd)
	allowed := []Algorithm{AlgEdDSA, AlgES256, AlgRS256}

	t.Run("alg none (CVE-2015-9235 class)", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "none", "kid": "ed-1"}, payload, nil)
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrAlgNotAllowed) {
			t.Errorf("want ErrAlgNotAllowed, got %v", err)
		}
	})

	t.Run("alg NONE case variant", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "NoNe", "kid": "ed-1"}, payload, []byte("x"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrAlgNotAllowed) {
			t.Errorf("want ErrAlgNotAllowed, got %v", err)
		}
	})

	t.Run("HS256 key confusion (CVE-2016-5431 class)", func(t *testing.T) {
		// Attacker signs with HMAC using the public key bytes as secret.
		// Irrelevant how it's signed: HS256 is simply not in the vocabulary.
		tok := forgeToken(t, map[string]any{"alg": "HS256", "kid": "ed-1"}, payload, []byte("hmac-ish"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrAlgNotAllowed) {
			t.Errorf("want ErrAlgNotAllowed, got %v", err)
		}
	})

	t.Run("alg swap against pinned key", func(t *testing.T) {
		// Token claims ES256 for a key the verifier knows is EdDSA.
		skEC, _ := newECKey(t, "ed-1")
		tok, err := Sign(payload, skEC)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrAlgMismatch) {
			t.Errorf("want ErrAlgMismatch, got %v", err)
		}
	})

	t.Run("embedded jwk header (CVE-2018-0114 class)", func(t *testing.T) {
		// Attacker embeds their own public key in the header.
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		hdr := map[string]any{
			"alg": "EdDSA", "kid": "ed-1",
			"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(pub)},
		}
		rawHdr, _ := json.Marshal(hdr)
		signingInput := b64.EncodeToString(rawHdr) + "." + b64.EncodeToString(payload)
		sig := ed25519.Sign(priv, []byte(signingInput))
		tok := signingInput + "." + b64.EncodeToString(sig)
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrHeaderRejected) {
			t.Errorf("want ErrHeaderRejected, got %v", err)
		}
	})

	t.Run("jku URL dereference", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "EdDSA", "kid": "ed-1", "jku": "https://evil.example/jwks"}, payload, []byte("sig"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrHeaderRejected) {
			t.Errorf("want ErrHeaderRejected, got %v", err)
		}
	})

	t.Run("crit downgrade", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "EdDSA", "kid": "ed-1", "crit": []string{"exp"}}, payload, []byte("sig"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrHeaderRejected) {
			t.Errorf("want ErrHeaderRejected, got %v", err)
		}
	})

	t.Run("unknown header parameter", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "EdDSA", "kid": "ed-1", "zip": "DEF"}, payload, []byte("sig"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrHeaderRejected) {
			t.Errorf("want ErrHeaderRejected, got %v", err)
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "EdDSA"}, payload, []byte("sig"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrKidMissing) {
			t.Errorf("want ErrKidMissing, got %v", err)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		tok := forgeToken(t, map[string]any{"alg": "EdDSA", "kid": "ghost"}, payload, []byte("sig"))
		if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("want ErrUnknownKey, got %v", err)
		}
	})

	t.Run("alg allowed by package but not by caller", func(t *testing.T) {
		// Caller only accepts EdDSA; a genuine RS256 token must be refused.
		skRSA, vkRSA := newRSAKey(t, "rsa-1")
		tok, err := Sign(payload, skRSA)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(tok, resolverFor(t, vkEd, vkRSA), []Algorithm{AlgEdDSA}); !errors.Is(err, ErrAlgNotAllowed) {
			t.Errorf("want ErrAlgNotAllowed, got %v", err)
		}
	})

	t.Run("standard base64 with padding rejected", func(t *testing.T) {
		parts := strings.Split(genuine, ".")
		raw, _ := b64.DecodeString(parts[0])
		padded := base64.URLEncoding.EncodeToString(raw) // includes '='
		if padded == parts[0] {
			t.Skip("no padding difference for this header length")
		}
		tok := padded + "." + parts[1] + "." + parts[2]
		if _, _, err := Verify(tok, resolver, allowed); err == nil {
			t.Error("padded base64 accepted")
		}
	})

	t.Run("wrong segment count", func(t *testing.T) {
		for _, tok := range []string{"a.b", "a.b.c.d", "", genuine + "."} {
			if _, _, err := Verify(tok, resolver, allowed); !errors.Is(err, ErrMalformed) {
				t.Errorf("token %q: want ErrMalformed, got %v", tok, err)
			}
		}
	})

	t.Run("ES256 oversized signature", func(t *testing.T) {
		skEC, vkEC := newECKey(t, "ec-1")
		tok, err := Sign(payload, skEC)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(tok, ".")
		sig, _ := b64.DecodeString(parts[2])
		long := append(sig, 0x00)
		forged := parts[0] + "." + parts[1] + "." + b64.EncodeToString(long)
		if _, _, err := Verify(forged, resolverFor(t, vkEC), []Algorithm{AlgES256}); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("want ErrSignatureInvalid, got %v", err)
		}
	})
}

func TestSignRejectsWeakRSA(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Sign([]byte("p"), SigningKey{ID: "weak", Alg: AlgRS256, Private: weak})
	if err == nil {
		t.Fatal("1024-bit RSA signing key accepted")
	}
}

func TestSignRejectsHeaderInjectionViaKeyID(t *testing.T) {
	// A hostile kid containing JSON must be escaped, not injected.
	sk, vk := newEdKey(t, `evil","alg":"none`)
	tok, err := Sign([]byte(`{}`), sk)
	if err != nil {
		t.Fatal(err)
	}
	_, hdr, err := Verify(tok, resolverFor(t, vk), []Algorithm{AlgEdDSA})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if hdr.Kid != `evil","alg":"none` {
		t.Errorf("kid mangled: %q", hdr.Kid)
	}
}
