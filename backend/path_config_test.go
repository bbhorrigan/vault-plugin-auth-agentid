package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathConfig_ReadEmpty(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty config returns nil response
	if resp != nil {
		t.Errorf("expected nil response for empty config, got: %v", resp)
	}
}

func TestPathConfig_Write(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":   []string{"https://issuer1.example.com", "https://issuer2.example.com"},
			"default_ttl":       600,
			"max_ttl":           7200,
			"required_audience": "https://vault.example.com",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Read it back
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
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
	if resp.Data["default_ttl"].(int) != 600 {
		t.Errorf("expected default_ttl=600, got %v", resp.Data["default_ttl"])
	}
	if resp.Data["max_ttl"].(int) != 7200 {
		t.Errorf("expected max_ttl=7200, got %v", resp.Data["max_ttl"])
	}
	if resp.Data["required_audience"].(string) != "https://vault.example.com" {
		t.Errorf("expected required_audience='https://vault.example.com', got %v", resp.Data["required_audience"])
	}

	issuers := resp.Data["trusted_issuers"].([]string)
	if len(issuers) != 2 {
		t.Errorf("expected 2 trusted_issuers, got %d", len(issuers))
	}
}

func TestPathConfig_InvalidTTL(t *testing.T) {
	b, storage := getTestBackend(t)

	// Try to set default_ttl > max_ttl
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers": []string{"https://issuer.example.com"},
			"default_ttl":     7200,
			"max_ttl":         600,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid TTL config")
	}

	if resp.Data["error"] != "default_ttl cannot exceed max_ttl" {
		t.Errorf("unexpected error message: %v", resp.Data["error"])
	}
}

func TestPathConfig_Delete(t *testing.T) {
	b, storage := getTestBackend(t)

	// First write some config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers": []string{"https://issuer.example.com"},
		},
	}

	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete it
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}

	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response after delete, got: %v", resp)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.DefaultTTL != 300 {
		t.Errorf("expected DefaultTTL=300, got %d", config.DefaultTTL)
	}

	if config.MaxTTL != 3600 {
		t.Errorf("expected MaxTTL=3600, got %d", config.MaxTTL)
	}

	if len(config.AllowedAlgorithms) != 3 {
		t.Errorf("expected 3 AllowedAlgorithms, got %d", len(config.AllowedAlgorithms))
	}
}

