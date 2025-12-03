package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// getTestBackend creates a backend for testing
func getTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	config := &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal:  300,
			MaxLeaseTTLVal:      3600,
			LocalMountVal:       false,
			ReplicationStateVal: 0,
		},
		StorageView: &logical.InmemStorage{},
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b.(*backend), config.StorageView
}

func TestFactory(t *testing.T) {
	b, _ := getTestBackend(t)

	if b == nil {
		t.Fatal("backend is nil")
	}

	if b.Backend == nil {
		t.Fatal("framework backend is nil")
	}

	if b.Backend.BackendType != logical.TypeCredential {
		t.Errorf("expected BackendType to be TypeCredential, got %v", b.Backend.BackendType)
	}
}

func TestBackend_Paths(t *testing.T) {
	b, _ := getTestBackend(t)

	paths := b.Backend.Paths

	if len(paths) == 0 {
		t.Fatal("no paths registered")
	}

	// Check that expected paths are registered
	expectedPatterns := []string{
		"login",
		"config",
		"jwks/",
	}

	for _, expected := range expectedPatterns {
		found := false
		for _, p := range paths {
			if p.Pattern == expected || p.Pattern == "jwks/"+`(?P<issuer>\w(([\w-.]+)?\w)?)` || p.Pattern == "jwks/?$" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected path pattern %q not found", expected)
		}
	}
}

