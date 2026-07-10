package memory_test

import (
	"testing"

	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/idp/internal/storage/memory"
	"github.com/aikazzh/portfolio/idp/internal/storage/storagetest"
)

// The memory store is what every server test runs against, so it is the
// reference implementation of the contract. postgres runs the same suite under
// -tags integration.
func TestStoreContract(t *testing.T) {
	storagetest.RunStoreContract(t, func(*testing.T) storage.Store { return memory.New() })
}
