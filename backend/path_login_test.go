package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	_, _ = b.HandleRequest(context.Background(), configReq)

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

	issuer := "test-issuer"

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

	// Add JWKS with static key - path must match the issuer name
	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
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

	issuer := "test-issuer"

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
	_, _ = b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, _ = b.HandleRequest(context.Background(), jwksReq)

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
	_, _ = b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/untrusted-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, _ = b.HandleRequest(context.Background(), jwksReq)

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

func TestPathLogin_RSAKey(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
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

	issuer := "test-issuer-rsa"

	// Configure trusted issuer
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"RS256"},
		},
	}
	_, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Add JWKS with static key
	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "rsa-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, err = b.HandleRequest(context.Background(), jwksReq)
	if err != nil {
		t.Fatalf("failed to configure JWKS: %v", err)
	}

	// Create a test JWT with RSA
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "did:web:rsa-agent.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Intent:  "read",
		AgentID: "rsa-agent-123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "rsa-key-1"

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

	if resp.Auth.DisplayName != "rsa-agent-123" {
		t.Errorf("expected DisplayName='rsa-agent-123', got %q", resp.Auth.DisplayName)
	}
}

func TestPathLogin_EdDSAKey(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	issuer := "test-issuer-eddsa"

	// Configure trusted issuer
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"EdDSA"},
		},
	}
	_, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Add JWKS with static key
	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "eddsa-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, err = b.HandleRequest(context.Background(), jwksReq)
	if err != nil {
		t.Fatalf("failed to configure JWKS: %v", err)
	}

	// Create a test JWT with EdDSA
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "did:web:eddsa-agent.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Intent:  "write",
		AgentID: "eddsa-agent-123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "eddsa-key-1"

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

	if resp.Auth.DisplayName != "eddsa-agent-123" {
		t.Errorf("expected DisplayName='eddsa-agent-123', got %q", resp.Auth.DisplayName)
	}
}

func TestPathLogin_AudienceValidation(t *testing.T) {
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

	issuer := "test-issuer"
	requiredAudience := "https://vault.example.com"

	// Configure with required audience
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"ES256"},
			"required_audience":  requiredAudience,
		},
	}
	_, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, _ = b.HandleRequest(context.Background(), jwksReq)

	t.Run("matching audience", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				Audience:  jwt.ClaimStrings{requiredAudience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			AgentID: "test-agent",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

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

		if resp.IsError() {
			t.Fatalf("expected success, got error: %v", resp.Error())
		}
	})

	t.Run("non-matching audience", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				Audience:  jwt.ClaimStrings{"https://other.example.com"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

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
			t.Fatal("expected error response for non-matching audience")
		}
	})

	t.Run("multiple audiences with one matching", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				Audience:  jwt.ClaimStrings{"https://other.example.com", requiredAudience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			AgentID: "test-agent",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

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

		if resp.IsError() {
			t.Fatalf("expected success with one matching audience, got error: %v", resp.Error())
		}
	})
}

func TestPathLogin_WithRole(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	issuer := "test-issuer"

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
	_, _ = b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, _ = b.HandleRequest(context.Background(), jwksReq)

	// Create a role
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"bound_issuers":   []string{issuer},
			"allowed_intents": []string{"read"},
			"token_policies":  []string{"custom-policy"},
			"token_ttl":       900,
		},
	}
	_, _ = b.HandleRequest(context.Background(), roleReq)

	t.Run("login with role - matching claims", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Intent:  "read",
			AgentID: "test-agent",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

		loginReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data: map[string]interface{}{
				"token": tokenString,
				"role":  "test-role",
			},
		}

		resp, err := b.HandleRequest(context.Background(), loginReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.IsError() {
			t.Fatalf("expected success, got error: %v", resp.Error())
		}

		// Verify role-specific policies
		hasCustomPolicy := false
		for _, p := range resp.Auth.Policies {
			if p == "custom-policy" {
				hasCustomPolicy = true
				break
			}
		}
		if !hasCustomPolicy {
			t.Errorf("expected 'custom-policy' in policies, got: %v", resp.Auth.Policies)
		}
	})

	t.Run("login with role - non-matching intent", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Intent: "admin", // Not allowed by role
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

		loginReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data: map[string]interface{}{
				"token": tokenString,
				"role":  "test-role",
			},
		}

		resp, err := b.HandleRequest(context.Background(), loginReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp == nil || !resp.IsError() {
			t.Fatal("expected error response for non-matching intent")
		}
	})

	t.Run("login with non-existent role", func(t *testing.T) {
		claims := &AgentClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "did:web:agent.example.com",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-1"
		tokenString, _ := token.SignedString(privateKey)

		loginReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data: map[string]interface{}{
				"token": tokenString,
				"role":  "non-existent-role",
			},
		}

		resp, err := b.HandleRequest(context.Background(), loginReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp == nil || !resp.IsError() {
			t.Fatal("expected error response for non-existent role")
		}
	})
}

func TestPathLogin_AlgorithmMismatch(t *testing.T) {
	b, storage := getTestBackend(t)

	// Generate an EC key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	issuer := "test-issuer"

	// Configure with only RS256 allowed (not ES256)
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"trusted_issuers":    []string{issuer},
			"allowed_algorithms": []string{"RS256"}, // Only RSA allowed
		},
	}
	_, _ = b.HandleRequest(context.Background(), configReq)

	jwksReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/" + issuer,
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "test-key-1",
			"public_key": string(pubKeyPEM),
		},
	}
	_, _ = b.HandleRequest(context.Background(), jwksReq)

	// Try to login with ES256 token (not allowed)
	claims := &AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "did:web:agent.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(privateKey)

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
		t.Fatal("expected error response for algorithm mismatch")
	}
}

