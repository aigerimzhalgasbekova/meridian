package jose

import (
	"testing"
)

func benchKeys(b *testing.B, alg Algorithm) (SigningKey, KeyResolver) {
	b.Helper()
	t := &testing.T{}
	var sk SigningKey
	var vk VerificationKey
	switch alg {
	case AlgEdDSA:
		sk, vk = newEdKey(t, "bench")
	case AlgES256:
		sk, vk = newECKey(t, "bench")
	case AlgRS256:
		sk, vk = newRSAKey(t, "bench")
	}
	set, err := NewKeySet(vk)
	if err != nil {
		b.Fatal(err)
	}
	return sk, set
}

func BenchmarkSign(b *testing.B) {
	payload := []byte(`{"iss":"https://idp.example","sub":"user-42","aud":"api","exp":1783000000,"scope":"openid profile email"}`)
	for _, alg := range []Algorithm{AlgEdDSA, AlgES256, AlgRS256} {
		b.Run(string(alg), func(b *testing.B) {
			sk, _ := benchKeys(b, alg)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Sign(payload, sk); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	payload := []byte(`{"iss":"https://idp.example","sub":"user-42","aud":"api","exp":1783000000,"scope":"openid profile email"}`)
	for _, alg := range []Algorithm{AlgEdDSA, AlgES256, AlgRS256} {
		b.Run(string(alg), func(b *testing.B) {
			sk, set := benchKeys(b, alg)
			token, err := Sign(payload, sk)
			if err != nil {
				b.Fatal(err)
			}
			allowed := []Algorithm{alg}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := Verify(token, set, allowed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
