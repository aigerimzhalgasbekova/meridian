package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Claims is a JWT claims set: the registered claims plus arbitrary private
// claims, marshalled as one flat JSON object.
type Claims struct {
	Issuer    string   `json:"-"`
	Subject   string   `json:"-"`
	Audience  []string `json:"-"`
	ExpiresAt int64    `json:"-"` // unix seconds; 0 = absent
	NotBefore int64    `json:"-"`
	IssuedAt  int64    `json:"-"`
	ID        string   `json:"-"` // jti

	// Extra holds private claims. Registered claim names in Extra are
	// rejected at marshal time to prevent ambiguity.
	Extra map[string]any `json:"-"`
}

var registeredNames = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true,
	"nbf": true, "iat": true, "jti": true,
}

// MarshalJSON flattens registered and private claims into one object.
func (c Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(c.Extra)+7)
	for k, v := range c.Extra {
		if registeredNames[k] {
			return nil, fmt.Errorf("jose: private claim %q collides with a registered claim", k)
		}
		m[k] = v
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	switch len(c.Audience) {
	case 0:
	case 1:
		m["aud"] = c.Audience[0]
	default:
		m["aud"] = c.Audience
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.ID != "" {
		m["jti"] = c.ID
	}
	return json.Marshal(m)
}

// UnmarshalJSON splits registered claims out of the flat object; everything
// else lands in Extra.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	take := func(name string, dst any) error {
		raw, ok := m[name]
		if !ok {
			return nil
		}
		delete(m, name)
		return json.Unmarshal(raw, dst)
	}
	if err := take("iss", &c.Issuer); err != nil {
		return fmt.Errorf("jose: iss: %w", err)
	}
	if err := take("sub", &c.Subject); err != nil {
		return fmt.Errorf("jose: sub: %w", err)
	}
	if raw, ok := m["aud"]; ok {
		delete(m, "aud")
		aud, err := parseAudience(raw)
		if err != nil {
			return err
		}
		c.Audience = aud
	}
	if err := take("exp", &c.ExpiresAt); err != nil {
		return fmt.Errorf("jose: exp: %w", err)
	}
	if err := take("nbf", &c.NotBefore); err != nil {
		return fmt.Errorf("jose: nbf: %w", err)
	}
	if err := take("iat", &c.IssuedAt); err != nil {
		return fmt.Errorf("jose: iat: %w", err)
	}
	if err := take("jti", &c.ID); err != nil {
		return fmt.Errorf("jose: jti: %w", err)
	}
	if len(m) > 0 {
		c.Extra = make(map[string]any, len(m))
		for k, raw := range m {
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("jose: claim %q: %w", k, err)
			}
			c.Extra[k] = v
		}
	}
	return nil
}

func parseAudience(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	return nil, errors.New("jose: aud must be a string or an array of strings")
}

// Expect describes the validation policy for a claims set.
type Expect struct {
	// Issuer, when set, must match iss exactly.
	Issuer string
	// Audience, when set, must appear in aud.
	Audience string
	// Now supplies the clock; defaults to time.Now. Injectable for tests.
	Now func() time.Time
	// Leeway absorbs clock skew for exp/nbf/iat checks. Default 0.
	Leeway time.Duration
	// AllowMissingExpiry permits tokens without exp. Off by default: an
	// unbounded token is almost always a bug.
	AllowMissingExpiry bool
	// MaxIssuedAge, when >0, rejects tokens whose iat is older than this,
	// regardless of exp.
	MaxIssuedAge time.Duration
}

// Claim-validation errors, comparable with errors.Is.
var (
	ErrExpired          = errors.New("jose: token expired")
	ErrNotYetValid      = errors.New("jose: token not yet valid")
	ErrIssuerMismatch   = errors.New("jose: issuer mismatch")
	ErrAudienceMismatch = errors.New("jose: audience mismatch")
	ErrMissingExpiry    = errors.New("jose: token has no exp claim")
	ErrIssuedTooOld     = errors.New("jose: token issued too long ago")
	ErrIssuedInFuture   = errors.New("jose: token issued in the future")
)

// Validate applies the policy in e to c.
func (c Claims) Validate(e Expect) error {
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	if c.ExpiresAt == 0 {
		if !e.AllowMissingExpiry {
			return ErrMissingExpiry
		}
	} else if now.Add(-e.Leeway).Unix() >= c.ExpiresAt {
		return ErrExpired
	}
	if c.NotBefore != 0 && now.Add(e.Leeway).Unix() < c.NotBefore {
		return ErrNotYetValid
	}
	if c.IssuedAt != 0 {
		if now.Add(e.Leeway).Unix() < c.IssuedAt {
			return ErrIssuedInFuture
		}
		if e.MaxIssuedAge > 0 && now.Add(-e.Leeway).Sub(time.Unix(c.IssuedAt, 0)) > e.MaxIssuedAge {
			return ErrIssuedTooOld
		}
	}
	if e.Issuer != "" && c.Issuer != e.Issuer {
		return fmt.Errorf("%w: got %q", ErrIssuerMismatch, c.Issuer)
	}
	if e.Audience != "" {
		found := false
		for _, aud := range c.Audience {
			if aud == e.Audience {
				found = true
				break
			}
		}
		if !found {
			return ErrAudienceMismatch
		}
	}
	return nil
}

// SignClaims marshals claims and signs them as a JWT.
func SignClaims(c Claims, key SigningKey) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return Sign(payload, key)
}

// VerifyClaims verifies token signature and claims in one call.
func VerifyClaims(token string, resolver KeyResolver, allowed []Algorithm, e Expect) (Claims, error) {
	payload, _, err := Verify(token, resolver, allowed)
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if err := c.Validate(e); err != nil {
		return Claims{}, err
	}
	return c, nil
}
