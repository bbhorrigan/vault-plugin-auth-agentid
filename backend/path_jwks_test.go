package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func generateTestKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))
}

func TestPathJWKS_WriteWithURL(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"jwks_url": "https://issuer.example.com/.well-known/jwks.json",
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
		Path:      "jwks/my-issuer",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	if resp.Data["jwks_url"] != "https://issuer.example.com/.well-known/jwks.json" {
		t.Errorf("expected jwks_url, got: %v", resp.Data["jwks_url"])
	}
}

func TestPathJWKS_WriteWithPublicKey(t *testing.T) {
	b, storage := getTestBackend(t)

	pubKeyPEM := generateTestKeyPEM(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "key-2024",
			"public_key": pubKeyPEM,
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
		Path:      "jwks/my-issuer",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Data["public_keys"] == nil {
		t.Fatal("expected public_keys in response")
	}

	keys := resp.Data["public_keys"].(map[string]string)
	if _, ok := keys["key-2024"]; !ok {
		t.Error("expected key-2024 in public_keys")
	}
}

func TestPathJWKS_WriteRequiresKidForPublicKey(t *testing.T) {
	b, storage := getTestBackend(t)

	pubKeyPEM := generateTestKeyPEM(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"public_key": pubKeyPEM,
			// Missing kid!
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when kid is missing")
	}
}

func TestPathJWKS_WriteRequiresURLOrKey(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data:      map[string]interface{}{
			// Neither jwks_url nor public_key provided
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when neither URL nor key provided")
	}
}

func TestPathJWKS_InvalidPublicKey(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"kid":        "key-1",
			"public_key": "not a valid PEM",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid public key")
	}
}

func TestPathJWKS_Delete(t *testing.T) {
	b, storage := getTestBackend(t)

	// First create one
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
		Data: map[string]interface{}{
			"jwks_url": "https://issuer.example.com/.well-known/jwks.json",
		},
	}
	b.HandleRequest(context.Background(), req)

	// Delete it
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "jwks/my-issuer",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	// Verify it's gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks/my-issuer",
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

func TestPathJWKS_List(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a few issuers
	issuers := []string{"issuer-a", "issuer-b", "issuer-c"}
	for _, issuer := range issuers {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "jwks/" + issuer,
			Storage:   storage,
			Data: map[string]interface{}{
				"jwks_url": "https://" + issuer + ".example.com/.well-known/jwks.json",
			},
		}
		b.HandleRequest(context.Background(), req)
	}

	// List them
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "jwks/",
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
		t.Errorf("expected 3 issuers, got %d", len(keys))
	}
}

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
		hasError bool
	}{
		{"SGVsbG8", []byte("Hello"), false},
		{"SGVsbG8gV29ybGQ", []byte("Hello World"), false},
		{"", []byte(""), false},
	}

	for _, tt := range tests {
		result, err := base64URLDecode(tt.input)
		if tt.hasError && err == nil {
			t.Errorf("expected error for input %q", tt.input)
		}
		if !tt.hasError && err != nil {
			t.Errorf("unexpected error for input %q: %v", tt.input, err)
		}
		if string(result) != string(tt.expected) {
			t.Errorf("expected %q, got %q", tt.expected, result)
		}
	}
}

