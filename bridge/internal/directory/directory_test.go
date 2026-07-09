package directory

import (
	"errors"
	"testing"
)

func TestMatchByProviderSubjectNeverEmail(t *testing.T) {
	s := NewMemStore(nil)
	a, err := s.CreateIdentity("alice@example.com", "Alice",
		Link{Provider: "google", Subject: "g-sub-1", Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("same provider+subject resolves", func(t *testing.T) {
		got, err := s.IdentityByLink("google", "g-sub-1")
		if err != nil || got.ID != a.ID {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	t.Run("same email via different provider does NOT resolve", func(t *testing.T) {
		if _, err := s.IdentityByLink("entra", "e-sub-9"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("email must never match a login: %v", err)
		}
	})

	t.Run("email collision creates a separate identity", func(t *testing.T) {
		b, err := s.CreateIdentity("alice@example.com", "Alice",
			Link{Provider: "entra", Subject: "e-sub-9", Email: "alice@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if b.ID == a.ID {
			t.Fatal("identities auto-merged on email — account-takeover vector")
		}
		same, _ := s.IdentitiesByEmail("alice@example.com")
		if len(same) != 2 {
			t.Fatalf("expected 2 identities sharing the email, got %d", len(same))
		}
	})
}

func TestLinking(t *testing.T) {
	s := NewMemStore(nil)
	a, _ := s.CreateIdentity("a@x.com", "A", Link{Provider: "google", Subject: "s1"})
	b, _ := s.CreateIdentity("b@x.com", "B", Link{Provider: "google", Subject: "s2"})

	if err := s.AddLink(a.ID, Link{Provider: "entra", Subject: "e1"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.IdentityByLink("entra", "e1")
	if err != nil || got.ID != a.ID {
		t.Fatalf("linked login resolves wrong: %+v, %v", got, err)
	}
	links, _ := s.Links(a.ID)
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}

	t.Run("upstream account cannot be linked twice", func(t *testing.T) {
		if err := s.AddLink(b.ID, Link{Provider: "entra", Subject: "e1"}); !errors.Is(err, ErrAlreadyLinked) {
			t.Fatalf("got %v, want ErrAlreadyLinked", err)
		}
		if err := s.AddLink(b.ID, Link{Provider: "google", Subject: "s1"}); !errors.Is(err, ErrAlreadyLinked) {
			t.Fatalf("got %v, want ErrAlreadyLinked", err)
		}
	})

	t.Run("link to unknown identity fails", func(t *testing.T) {
		if err := s.AddLink("idn_nope", Link{Provider: "entra", Subject: "e2"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}
