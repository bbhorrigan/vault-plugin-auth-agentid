package backend

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathRoles_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a role
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"bound_subjects":  []string{"did:web:agent.example.com"},
			"bound_issuers":   []string{"https://issuer.example.com"},
			"token_policies":  []string{"agent-read", "agent-write"},
			"token_ttl":       600,
			"token_max_ttl":   3600,
			"allowed_intents": []string{"read", "write"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read the role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify values
	if resp.Data["name"] != "test-role" {
		t.Errorf("expected name='test-role', got %v", resp.Data["name"])
	}

	policies := resp.Data["token_policies"].([]string)
	if len(policies) != 2 {
		t.Errorf("expected 2 token_policies, got %d", len(policies))
	}

	if resp.Data["token_ttl"].(int) != 600 {
		t.Errorf("expected token_ttl=600, got %v", resp.Data["token_ttl"])
	}

	// Update the role
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"token_ttl": 900,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify update
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Data["token_ttl"].(int) != 900 {
		t.Errorf("expected token_ttl=900 after update, got %v", resp.Data["token_ttl"])
	}

	// Delete the role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deletion
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response after delete, got: %v", resp)
	}
}

func TestPathRoles_List(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a few roles
	roles := []string{"role-a", "role-b", "role-c"}
	for _, role := range roles {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/" + role,
			Storage:   storage,
			Data: map[string]interface{}{
				"token_policies": []string{"default"},
			},
		}
		_, _ = b.HandleRequest(context.Background(), req)
	}

	// List them
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	keys := resp.Data["keys"].([]string)
	if len(keys) != 3 {
		t.Errorf("expected 3 roles, got %d", len(keys))
	}
}

func TestPathRoles_InvalidTTL(t *testing.T) {
	b, storage := getTestBackend(t)

	// Try to create a role with token_ttl > token_max_ttl
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"token_ttl":     7200,
			"token_max_ttl": 3600,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid TTL config")
	}
}

func TestPathRoles_BoundClaims(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a role with bound claims
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"bound_claims": map[string]string{
				"intent":     "read,write",
				"mcp_server": "*.example.com",
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read and verify
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boundClaims := resp.Data["bound_claims"].(map[string][]string)
	if len(boundClaims) != 2 {
		t.Errorf("expected 2 bound claims, got %d", len(boundClaims))
	}

	intentValues := boundClaims["intent"]
	if len(intentValues) != 2 {
		t.Errorf("expected 2 intent values, got %d", len(intentValues))
	}
}

func TestValidateAgainstRole(t *testing.T) {
	b := &backend{}

	tests := []struct {
		name      string
		role      *RoleConfig
		claims    *AgentClaims
		shouldErr bool
	}{
		{
			name: "matching subject",
			role: &RoleConfig{
				BoundSubjects: []string{"did:web:agent.example.com"},
			},
			claims: &AgentClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "did:web:agent.example.com",
				},
			},
			shouldErr: false,
		},
		{
			name: "non-matching subject",
			role: &RoleConfig{
				BoundSubjects: []string{"did:web:other.example.com"},
			},
			claims: &AgentClaims{
				AgentDID: "did:web:agent.example.com",
			},
			shouldErr: true,
		},
		{
			name: "matching issuer",
			role: &RoleConfig{
				BoundIssuers: []string{"https://issuer.example.com"},
			},
			claims: &AgentClaims{},
			shouldErr: true, // Empty issuer doesn't match
		},
		{
			name: "matching intent",
			role: &RoleConfig{
				AllowedIntents: []string{"read", "write"},
			},
			claims: &AgentClaims{
				Intent: "read",
			},
			shouldErr: false,
		},
		{
			name: "non-matching intent",
			role: &RoleConfig{
				AllowedIntents: []string{"read"},
			},
			claims: &AgentClaims{
				Intent: "admin",
			},
			shouldErr: true,
		},
		{
			name: "no bound claims (allow all)",
			role: &RoleConfig{},
			claims: &AgentClaims{
				AgentID: "any-agent",
				Intent:  "anything",
			},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.validateAgainstRole(tt.role, tt.claims)
			if tt.shouldErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern  string
		value    string
		expected bool
	}{
		{"exact", "exact", true},
		{"exact", "different", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"api.*", "api.example.com", true},
		{"*test*", "this-is-a-test-value", true},
		{"*test*", "no-match-here", false},
		{"prefix*", "prefix-something", true},
		{"prefix*", "something-prefix", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			result := matchGlob(tt.pattern, tt.value)
			if result != tt.expected {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, result, tt.expected)
			}
		})
	}
}


