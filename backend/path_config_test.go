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

	if config.JWKSCacheTTL != 300 {
		t.Errorf("expected JWKSCacheTTL=300, got %d", config.JWKSCacheTTL)
	}

	if config.ClockSkewLeeway != 60 {
		t.Errorf("expected ClockSkewLeeway=60, got %d", config.ClockSkewLeeway)
	}

	if config.AllowInsecureJWKS != false {
		t.Errorf("expected AllowInsecureJWKS=false, got %v", config.AllowInsecureJWKS)
	}

	if config.JWKSRequestTimeout != 10 {
		t.Errorf("expected JWKSRequestTimeout=10, got %d", config.JWKSRequestTimeout)
	}
}

func TestPathConfig_NewOptions(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config with new options
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":      []string{"https://issuer.example.com"},
			"jwks_cache_ttl":       600,
			"clock_skew_leeway":    120,
			"allow_insecure_jwks":  true,
			"jwks_request_timeout": 30,
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

	// Verify new values
	if resp.Data["jwks_cache_ttl"].(int) != 600 {
		t.Errorf("expected jwks_cache_ttl=600, got %v", resp.Data["jwks_cache_ttl"])
	}
	if resp.Data["clock_skew_leeway"].(int) != 120 {
		t.Errorf("expected clock_skew_leeway=120, got %v", resp.Data["clock_skew_leeway"])
	}
	if resp.Data["allow_insecure_jwks"].(bool) != true {
		t.Errorf("expected allow_insecure_jwks=true, got %v", resp.Data["allow_insecure_jwks"])
	}
	if resp.Data["jwks_request_timeout"].(int) != 30 {
		t.Errorf("expected jwks_request_timeout=30, got %v", resp.Data["jwks_request_timeout"])
	}
}

func TestPathConfig_InvalidJWKSCacheTTL(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers": []string{"https://issuer.example.com"},
			"jwks_cache_ttl":  -1,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for negative jwks_cache_ttl")
	}
}

