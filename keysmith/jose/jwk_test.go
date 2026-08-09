package jose

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestJWKRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		mk   func(t *testing.T, id string) (SigningKey, VerificationKey)
	}{
		{"EdDSA", newEdKey},
		{"ES256", newECKey},
		{"RS256", newRSAKey},
	}
	payload := []byte(`{"sub":"alice"}`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sk, vk := tc.mk(t, "k1")
			jwk, err := PublicJWK(vk)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := json.Marshal(JWKS{Keys: []JWK{jwk}})
			if err != nil {
				t.Fatal(err)
			}
			set, err := ParseJWKS(doc)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := Sign(payload, sk)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Verify(tok, set, []Algorithm{sk.Alg}); err != nil {
				t.Errorf("verify via JWKS round trip: %v", err)
			}
		})
	}
}

func TestParseJWKSRejectsBadKeys(t *testing.T) {
	_, vk := newECKey(t, "ec-1")
	good, err := PublicJWK(vk)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("off-curve point", func(t *testing.T) {
		bad := good
		x := new(big.Int).SetBytes(mustB64(t, bad.X))
		x.Add(x, big.NewInt(1))
		buf := make([]byte, 32)
		bad.X = b64.EncodeToString(x.FillBytes(buf))
		doc, _ := json.Marshal(JWKS{Keys: []JWK{bad}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Error("off-curve EC point accepted")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		bad := good
		bad.Kid = ""
		doc, _ := json.Marshal(JWKS{Keys: []JWK{bad}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Error("kid-less JWK accepted")
		}
	})

	t.Run("alg kty mismatch", func(t *testing.T) {
		bad := good
		bad.Alg = string(AlgRS256) // EC key claiming RS256
		doc, _ := json.Marshal(JWKS{Keys: []JWK{bad}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Error("EC key with RSA alg accepted")
		}
	})

	t.Run("unsupported alg", func(t *testing.T) {
		bad := good
		bad.Alg = "ES512"
		doc, _ := json.Marshal(JWKS{Keys: []JWK{bad}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Error("ES512 accepted")
		}
	})

	t.Run("weak RSA modulus", func(t *testing.T) {
		doc, _ := json.Marshal(JWKS{Keys: []JWK{{
			Kty: "RSA", Kid: "weak", Alg: string(AlgRS256),
			N: b64.EncodeToString(make([]byte, 64)), // 512-bit modulus
			E: b64.EncodeToString([]byte{1, 0, 1}),
		}}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Error("512-bit RSA key accepted")
		}
	})

	t.Run("identical duplicate kid collapses, does not fail the set", func(t *testing.T) {
		// RFC 7517 §4.5 only says kid SHOULD be distinct; a JWKS we do not
		// control may repeat one. Byte-identical duplicates are harmless.
		doc, _ := json.Marshal(JWKS{Keys: []JWK{good, good}})
		set, err := ParseJWKS(doc)
		if err != nil {
			t.Fatalf("duplicate kid took the whole set down: %v", err)
		}
		if set.Len() != 1 {
			t.Errorf("set has %d keys, want 1", set.Len())
		}
	})

	t.Run("conflicting duplicate kid drops the kid, keeps the rest", func(t *testing.T) {
		// Same kid, different key material: picking either half silently is a
		// coin flip that can install a stale key over the live one. The kid
		// must vanish from the set (fail closed for its tokens) without
		// taking the other keys down.
		_, vk2 := newECKey(t, "ec-1") // fresh material under the same kid
		imposter, err := PublicJWK(vk2)
		if err != nil {
			t.Fatal(err)
		}
		_, vkOther := newEdKey(t, "ed-1")
		other, err := PublicJWK(vkOther)
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := json.Marshal(JWKS{Keys: []JWK{good, imposter, other}})
		set, err := ParseJWKS(doc)
		if err != nil {
			t.Fatalf("conflicting kid took the whole set down: %v", err)
		}
		if set.Len() != 1 {
			t.Errorf("set has %d keys, want 1 (only ed-1)", set.Len())
		}
		if _, err := set.VerificationKey("ec-1"); err == nil {
			t.Error("ambiguous kid served a key instead of failing closed")
		}
		if _, err := set.VerificationKey("ed-1"); err != nil {
			t.Errorf("unrelated key lost: %v", err)
		}
	})

	t.Run("encryption-use key rejected", func(t *testing.T) {
		// A key the provider marked use:"enc" (commonly published alg-less)
		// must never enter a verification set, or any signature made with the
		// provider's encryption key becomes an accepted login.
		enc := good
		enc.Kid, enc.Use, enc.Alg = "enc-1", "enc", ""
		doc, _ := json.Marshal(JWKS{Keys: []JWK{good, enc}})
		set, err := ParseJWKS(doc)
		if err != nil {
			t.Fatalf("enc key took the whole set down: %v", err)
		}
		if _, err := set.VerificationKey("enc-1"); err == nil {
			t.Error("use:enc key entered the verification set")
		}
	})

	t.Run("key_ops without verify rejected", func(t *testing.T) {
		ops := good
		ops.Kid, ops.KeyOps = "ops-1", []string{"encrypt", "wrapKey"}
		doc, _ := json.Marshal(JWKS{Keys: []JWK{good, ops}})
		set, err := ParseJWKS(doc)
		if err != nil {
			t.Fatalf("key_ops key took the whole set down: %v", err)
		}
		if _, err := set.VerificationKey("ops-1"); err == nil {
			t.Error("key without verify in key_ops entered the verification set")
		}
	})

	t.Run("oversized RSA modulus", func(t *testing.T) {
		// Unbounded above is remote CPU exhaustion: modular exponentiation
		// cost grows superlinearly and the document stays tiny.
		n := make([]byte, (MaxRSABits/8)+1)
		n[0] = 0xff
		doc, _ := json.Marshal(JWKS{Keys: []JWK{{
			Kty: "RSA", Kid: "huge", Alg: string(AlgRS256),
			N: b64.EncodeToString(n),
			E: b64.EncodeToString([]byte{1, 0, 1}),
		}}})
		if _, err := ParseJWKS(doc); err == nil {
			t.Errorf("RSA key above %d bits accepted", MaxRSABits)
		}
	})
}

func TestParseJWKSKeepsUsableKeys(t *testing.T) {
	// A key set is heterogeneous by nature and comes from providers we do not
	// control: one key this profile cannot use must not discard the rest.
	_, vk := newEdKey(t, "good-1")
	good, err := PublicJWK(vk)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7517 makes `alg` optional and real providers (Entra ID) omit it: an
	// alg-less key is usable, its algorithm fixed by kty/crv.
	noAlg := good
	noAlg.Kid, noAlg.Alg = "no-alg", ""
	unsupported := good // e.g. an upstream rotating in P-384
	unsupported.Kid, unsupported.Crv = "p384", "P-384"

	doc, err := json.Marshal(JWKS{Keys: []JWK{noAlg, good, unsupported}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("one unusable key discarded the whole set: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("set has %d keys, want 2", set.Len())
	}
	for _, kid := range []string{"good-1", "no-alg"} {
		if _, err := set.VerificationKey(kid); err != nil {
			t.Errorf("usable key %q missing: %v", kid, err)
		}
	}
	if _, err := set.VerificationKey("p384"); err == nil {
		t.Error("unsupported key \"p384\" was accepted")
	}

	// Zero survivors is still an error: a genuinely broken provider must show.
	other := unsupported
	other.Kid = "p384-2"
	doc, err = json.Marshal(JWKS{Keys: []JWK{unsupported, other}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWKS(doc); err == nil {
		t.Error("a document with no usable keys parsed cleanly")
	}
}

func TestPublicJWKRejectsAlgKeyTypeMismatch(t *testing.T) {
	// The encoder must not emit a JWK its own decoder refuses.
	_, vk := newEdKey(t, "ed-1")
	vk.Alg = AlgRS256
	if _, err := PublicJWK(vk); err == nil {
		t.Error("Ed25519 key emitted with alg RS256")
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
