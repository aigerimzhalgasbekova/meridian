package jose

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

var epoch = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

func TestClaimsRoundTrip(t *testing.T) {
	in := Claims{
		Issuer:    "https://idp.example/realms/acme",
		Subject:   "user-42",
		Audience:  []string{"api", "web"},
		ExpiresAt: epoch.Add(time.Hour).Unix(),
		NotBefore: epoch.Unix(),
		IssuedAt:  epoch.Unix(),
		ID:        "jti-1",
		Extra:     map[string]any{"scope": "openid profile", "tenant": "acme"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Claims
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Issuer != in.Issuer || out.Subject != in.Subject || out.ID != in.ID {
		t.Errorf("mismatch: %+v", out)
	}
	if len(out.Audience) != 2 {
		t.Errorf("audience: %v", out.Audience)
	}
	if out.Extra["scope"] != "openid profile" {
		t.Errorf("extra: %v", out.Extra)
	}
}

func TestClaimsSingleAudienceMarshalsAsString(t *testing.T) {
	raw, err := json.Marshal(Claims{Audience: []string{"api"}, ExpiresAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, isString := m["aud"].(string); !isString {
		t.Errorf("single aud should marshal as string, got %T", m["aud"])
	}
}

func TestClaimsRejectsRegisteredNameCollision(t *testing.T) {
	_, err := json.Marshal(Claims{Extra: map[string]any{"iss": "spoof"}})
	if err == nil {
		t.Fatal("registered-name collision accepted")
	}
}

func TestClaimsAudienceForms(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"aud":"solo","exp":1}`), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "solo" {
		t.Errorf("string aud: %v", c.Audience)
	}
	if err := json.Unmarshal([]byte(`{"aud":42,"exp":1}`), &c); err == nil {
		t.Error("numeric aud accepted")
	}
}

func TestValidate(t *testing.T) {
	base := Claims{
		Issuer:    "https://idp.example",
		Audience:  []string{"api"},
		ExpiresAt: epoch.Add(10 * time.Minute).Unix(),
		NotBefore: epoch.Add(-time.Minute).Unix(),
		IssuedAt:  epoch.Add(-time.Minute).Unix(),
	}
	ok := Expect{Issuer: "https://idp.example", Audience: "api", Now: fixedNow(epoch)}

	if err := base.Validate(ok); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(c *Claims)
		expect  func(e *Expect)
		wantErr error
	}{
		{"expired", func(c *Claims) { c.ExpiresAt = epoch.Add(-time.Second).Unix() }, nil, ErrExpired},
		{"expiry exactly now", func(c *Claims) { c.ExpiresAt = epoch.Unix() }, nil, ErrExpired},
		{"expired within leeway", func(c *Claims) { c.ExpiresAt = epoch.Add(-30 * time.Second).Unix() },
			func(e *Expect) { e.Leeway = time.Minute }, nil},
		{"nbf future", func(c *Claims) { c.NotBefore = epoch.Add(time.Hour).Unix() }, nil, ErrNotYetValid},
		{"nbf future within leeway", func(c *Claims) { c.NotBefore = epoch.Add(30 * time.Second).Unix() },
			func(e *Expect) { e.Leeway = time.Minute }, nil},
		{"iat future", func(c *Claims) { c.IssuedAt = epoch.Add(time.Hour).Unix() }, nil, ErrIssuedInFuture},
		{"iat too old", func(c *Claims) { c.IssuedAt = epoch.Add(-2 * time.Hour).Unix() },
			func(e *Expect) { e.MaxIssuedAge = time.Hour }, ErrIssuedTooOld},
		{"missing exp", func(c *Claims) { c.ExpiresAt = 0 }, nil, ErrMissingExpiry},
		{"missing exp allowed", func(c *Claims) { c.ExpiresAt = 0 },
			func(e *Expect) { e.AllowMissingExpiry = true }, nil},
		{"wrong issuer", func(c *Claims) { c.Issuer = "https://evil.example" }, nil, ErrIssuerMismatch},
		{"wrong audience", func(c *Claims) { c.Audience = []string{"other"} }, nil, ErrAudienceMismatch},
		{"empty audience", func(c *Claims) { c.Audience = nil }, nil, ErrAudienceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, e := base, ok
			tc.mutate(&c)
			if tc.expect != nil {
				tc.expect(&e)
			}
			err := c.Validate(e)
			if tc.wantErr == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSignVerifyClaimsEndToEnd(t *testing.T) {
	sk, vk := newEdKey(t, "k1")
	claims := Claims{
		Issuer:    "https://idp.example",
		Subject:   "alice",
		Audience:  []string{"api"},
		ExpiresAt: epoch.Add(time.Hour).Unix(),
		IssuedAt:  epoch.Unix(),
	}
	tok, err := SignClaims(claims, sk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyClaims(tok, resolverFor(t, vk), []Algorithm{AlgEdDSA},
		Expect{Issuer: "https://idp.example", Audience: "api", Now: fixedNow(epoch)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice" {
		t.Errorf("subject: %q", got.Subject)
	}
	// Signature is checked before claims: an expired token with a bad
	// signature must report the signature error, not leak claim validity.
	_, err = VerifyClaims(tok+"x", resolverFor(t, vk), []Algorithm{AlgEdDSA},
		Expect{Now: fixedNow(epoch.Add(48 * time.Hour))})
	if errors.Is(err, ErrExpired) {
		t.Error("claim validation ran before signature verification")
	}
}
