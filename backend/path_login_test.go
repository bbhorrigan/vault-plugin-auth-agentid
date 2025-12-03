package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathLogin_MissingToken(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing token")
	}
}

func TestPathLogin_NotConfigured(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"token": "some.jwt.token",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when not configured")
	}

	if resp.Data["error"] != "auth method not configured - please configure trusted issuers first" {
		t.Errorf("unexpected error message: %v", resp.Data["error"])
	}
}

func TestPathLogin_NoTrustedIssuers(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure with empty issuers
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers": []string{},
		},
	}
	b.HandleRequest(context.Background(), configReq)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"token": "some.jwt.token",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when no trusted issuers")
	}
}

func TestPathLogin_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	issuer := "https://test-issuer.example.com"

	// Configure trusted issuer
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"ES256"},
		},
	}
	_, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Add JWKS with static key
	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/test-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, err = b.HandleRequest(context.Background(), jwksReq)
	if err != nil {
		t.Fatalf("failed to configure JWKS: %v", err)
	}

	// Create a test JWT
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "did:web:agent.example.com",
			Audience:  jwt.ClaimStrings{"https://vault.example.com"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Intent:   "read",
		AgentID:  "agent-123",
		ToolName: "vault-reader",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Login with the token
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"token": tokenString,
		},
	}

	resp, err := b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	if resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	if resp.Auth == nil {
		t.Fatal("expected Auth in response")
	}

	// Verify auth metadata
	if resp.Auth.DisplayName != "agent-123" {
		t.Errorf("expected DisplayName='agent-123', got %q", resp.Auth.DisplayName)
	}

	if resp.Auth.Metadata["intent"] != "read" {
		t.Errorf("expected intent='read' in metadata, got %q", resp.Auth.Metadata["intent"])
	}

	if resp.Auth.Metadata["tool_name"] != "vault-reader" {
		t.Errorf("expected tool_name='vault-reader' in metadata, got %q", resp.Auth.Metadata["tool_name"])
	}

	// Check policies - should include default and agent-read (from intent=read)
	hasDefault := false
	hasAgentRead := false
	for _, p := range resp.Auth.Policies {
		if p == "default" {
			hasDefault = true
		}
		if p == "agent-read" {
			hasAgentRead = true
		}
	}

	if !hasDefault {
		t.Error("expected 'default' policy")
	}
	if !hasAgentRead {
		t.Error("expected 'agent-read' policy for intent=read")
	}
}

func TestPathLogin_ExpiredToken(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	issuer := "https://test-issuer.example.com"

	// Configure
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"ES256"},
		},
	}
	b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/test-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	b.HandleRequest(context.Background(), jwksReq)

	// Create an expired JWT
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "did:web:agent.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired!
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"token": tokenString,
		},
	}

	resp, err := b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for expired token")
	}
}

func TestPathLogin_UntrustedIssuer(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Configure with one issuer
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{"https://trusted-issuer.example.com"},
			"allowed_algorithms": []string{"ES256"},
		},
	}
	b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/untrusted-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	b.HandleRequest(context.Background(), jwksReq)

	// Create a JWT from untrusted issuer
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://untrusted-issuer.example.com", // Not in trusted list!
			Subject:   "did:web:agent.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"token": tokenString,
		},
	}

	resp, err := b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for untrusted issuer")
	}
}

func TestIntentToPolicyMapping(t *testing.T) {
	tests := []struct {
		intent         string
		expectedPolicy string
	}{
		{"read", "agent-read"},
		{"query", "agent-read"},
		{"write", "agent-write"},
		{"update", "agent-write"},
		{"create", "agent-write"},
		{"admin", "agent-admin"},
		{"manage", "agent-admin"},
		{"refactor", "agent-code"},
		{"code", "agent-code"},
	}

	for _, tt := range tests {
		t.Run(tt.intent, func(t *testing.T) {
			config := DefaultConfig()
			claims := &AgentClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:  "test",
					Subject: "test-agent",
				},
				Intent: tt.intent,
			}

			b := &backend{}
			auth := b.buildAuthResponse(config, claims)

			found := false
			for _, p := range auth.Policies {
				if p == tt.expectedPolicy {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected policy %q for intent %q, got policies: %v", tt.expectedPolicy, tt.intent, auth.Policies)
			}
		})
	}
}

