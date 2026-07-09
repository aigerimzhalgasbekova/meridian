package oauth

import (
	"slices"
	"strings"
)

// Scopes is an ordered, duplicate-free scope list.
type Scopes []string

// ParseScopes splits an RFC 6749 §3.3 scope string (space-delimited),
// dropping duplicates while preserving first-seen order.
func ParseScopes(s string) Scopes {
	if s == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out Scopes
	for _, sc := range strings.Fields(s) {
		if !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return out
}

func (s Scopes) String() string { return strings.Join(s, " ") }

// Has reports whether scope is present.
func (s Scopes) Has(scope string) bool { return slices.Contains(s, scope) }

// Subtract returns the scopes in s that are not in allowed.
func (s Scopes) Subtract(allowed Scopes) Scopes {
	var out Scopes
	for _, sc := range s {
		if !allowed.Has(sc) {
			out = append(out, sc)
		}
	}
	return out
}

// Intersect returns the scopes present in both.
func (s Scopes) Intersect(other Scopes) Scopes {
	var out Scopes
	for _, sc := range s {
		if other.Has(sc) {
			out = append(out, sc)
		}
	}
	return out
}

// Standard OIDC scopes this server understands.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)
