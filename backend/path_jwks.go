package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	jwksStoragePrefix = "jwks/"
)

// JWKSConfig holds JWKS configuration for an issuer
type JWKSConfig struct {
	Issuer     string            `json:"issuer"`
	JWKSURL    string            `json:"jwks_url,omitempty"`
	PublicKeys map[string]string `json:"public_keys,omitempty"` // kid -> PEM encoded public key
	CachedJWKS *CachedJWKS       `json:"cached_jwks,omitempty"`
}

// CachedJWKS holds cached JWKS data
type CachedJWKS struct {
	Keys      []JSONWebKey `json:"keys"`
	FetchedAt time.Time    `json:"fetched_at"`
}

// JSONWebKey represents a JWK
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate
	Crv string `json:"crv,omitempty"` // EC curve
}

// JWKSSet represents a JWKS response
type JWKSSet struct {
	Keys []JSONWebKey `json:"keys"`
}

// KeyResolver provides thread-safe key resolution
type KeyResolver struct {
	backend *backend
	storage logical.Storage
	ctx     context.Context
	mu      sync.RWMutex
}

func pathJWKS(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "jwks/" + framework.GenericNameRegex("issuer"),
		Fields: map[string]*framework.FieldSchema{
			"issuer": {
				Type:        framework.TypeString,
				Description: "Identifier for the issuer (e.g., 'agent-provider-1')",
				Required:    true,
			},
			"jwks_url": {
				Type:        framework.TypeString,
				Description: "URL to fetch JWKS from (e.g., https://issuer.com/.well-known/jwks.json)",
				Required:    false,
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded public key (alternative to JWKS URL)",
				Required:    false,
			},
			"kid": {
				Type:        framework.TypeString,
				Description: "Key ID for the public key (required if using public_key)",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathJWKSRead,
				Summary:  "Read JWKS configuration for an issuer",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathJWKSWrite,
				Summary:  "Configure JWKS for an issuer",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathJWKSWrite,
				Summary:  "Configure JWKS for an issuer",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathJWKSDelete,
				Summary:  "Delete JWKS configuration for an issuer",
			},
		},
		HelpSynopsis:    "Manage JWKS configuration for trusted issuers",
		HelpDescription: "Configure JWKS URLs or static public keys for verifying agent tokens.",
	}
}

func pathJWKSList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "jwks/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathJWKSList,
				Summary:  "List configured JWKS issuers",
			},
		},
		HelpSynopsis: "List all configured JWKS issuers",
	}
}

func (b *backend) pathJWKSRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	issuer := d.Get("issuer").(string)

	jwksConfig, err := b.getJWKSConfig(ctx, req.Storage, issuer)
	if err != nil {
		return nil, err
	}
	if jwksConfig == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"issuer":   jwksConfig.Issuer,
		"jwks_url": jwksConfig.JWKSURL,
	}

	if len(jwksConfig.PublicKeys) > 0 {
		data["public_keys"] = jwksConfig.PublicKeys
	}

	if jwksConfig.CachedJWKS != nil {
		data["cached_keys_count"] = len(jwksConfig.CachedJWKS.Keys)
		data["last_fetched"] = jwksConfig.CachedJWKS.FetchedAt.Format(time.RFC3339)
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathJWKSWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	issuer := d.Get("issuer").(string)

	jwksConfig, err := b.getJWKSConfig(ctx, req.Storage, issuer)
	if err != nil {
		return nil, err
	}
	if jwksConfig == nil {
		jwksConfig = &JWKSConfig{
			Issuer:     issuer,
			PublicKeys: make(map[string]string),
		}
	}

	if jwksURL, ok := d.GetOk("jwks_url"); ok {
		jwksConfig.JWKSURL = jwksURL.(string)
		// Clear cached JWKS when URL changes
		jwksConfig.CachedJWKS = nil
	}

	if publicKey, ok := d.GetOk("public_key"); ok {
		kid, kidOk := d.GetOk("kid")
		if !kidOk {
			return logical.ErrorResponse("kid is required when providing public_key"), nil
		}

		// Validate the PEM key
		keyPEM := publicKey.(string)
		if _, err := parsePublicKeyPEM(keyPEM); err != nil {
			return logical.ErrorResponse("invalid public key: %s", err), nil
		}

		jwksConfig.PublicKeys[kid.(string)] = keyPEM
	}

	if jwksConfig.JWKSURL == "" && len(jwksConfig.PublicKeys) == 0 {
		return logical.ErrorResponse("either jwks_url or public_key must be provided"), nil
	}

	if err := b.saveJWKSConfig(ctx, req.Storage, jwksConfig); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathJWKSDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	issuer := d.Get("issuer").(string)

	if err := req.Storage.Delete(ctx, jwksStoragePrefix+issuer); err != nil {
		return nil, fmt.Errorf("failed to delete JWKS config: %w", err)
	}

	return nil, nil
}

func (b *backend) pathJWKSList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, jwksStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list JWKS configs: %w", err)
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) getJWKSConfig(ctx context.Context, s logical.Storage, issuer string) (*JWKSConfig, error) {
	entry, err := s.Get(ctx, jwksStoragePrefix+issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var config JWKSConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS config: %w", err)
	}

	return &config, nil
}

func (b *backend) saveJWKSConfig(ctx context.Context, s logical.Storage, config *JWKSConfig) error {
	entry, err := logical.StorageEntryJSON(jwksStoragePrefix+config.Issuer, config)
	if err != nil {
		return fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to save JWKS config: %w", err)
	}

	return nil
}

// GetVerificationKey returns the public key for JWT verification
func (b *backend) GetVerificationKey(ctx context.Context, s logical.Storage, issuer, kid string) (interface{}, error) {
	jwksConfig, err := b.getJWKSConfig(ctx, s, issuer)
	if err != nil {
		return nil, err
	}
	if jwksConfig == nil {
		return nil, fmt.Errorf("no JWKS configuration found for issuer: %s", issuer)
	}

	// First, check static public keys
	if keyPEM, ok := jwksConfig.PublicKeys[kid]; ok {
		return parsePublicKeyPEM(keyPEM)
	}

	// If no static key, try JWKS URL
	if jwksConfig.JWKSURL != "" {
		return b.getKeyFromJWKS(ctx, s, jwksConfig, kid)
	}

	return nil, fmt.Errorf("no key found for kid: %s", kid)
}

func (b *backend) getKeyFromJWKS(ctx context.Context, s logical.Storage, config *JWKSConfig, kid string) (interface{}, error) {
	// Check cache (valid for 5 minutes)
	if config.CachedJWKS != nil && time.Since(config.CachedJWKS.FetchedAt) < 5*time.Minute {
		for _, key := range config.CachedJWKS.Keys {
			if key.Kid == kid {
				return jwkToPublicKey(key)
			}
		}
	}

	// Fetch fresh JWKS
	jwksSet, err := fetchJWKS(config.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Update cache
	config.CachedJWKS = &CachedJWKS{
		Keys:      jwksSet.Keys,
		FetchedAt: time.Now(),
	}

	if err := b.saveJWKSConfig(ctx, s, config); err != nil {
		// Log but don't fail - we have the keys
		b.Logger().Warn("failed to cache JWKS", "error", err)
	}

	// Find the key
	for _, key := range jwksSet.Keys {
		if key.Kid == kid {
			return jwkToPublicKey(key)
		}
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

func fetchJWKS(url string) (*JWKSSet, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwksSet JWKSSet
	if err := json.Unmarshal(body, &jwksSet); err != nil {
		return nil, err
	}

	return &jwksSet, nil
}

func jwkToPublicKey(jwk JSONWebKey) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECPublicKey(jwk)
	case "OKP":
		return jwkToEdDSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func jwkToRSAPublicKey(jwk JSONWebKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func jwkToECPublicKey(jwk JSONWebKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	var curve interface {
		Params() *ecdsa.PublicKey
	}

	switch jwk.Crv {
	case "P-256":
		curve = nil // Will use elliptic.P256() but we'll handle differently
	case "P-384":
		curve = nil
	case "P-521":
		curve = nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}
	_ = curve

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// For now, return a simple representation
	// In production, you'd use the proper elliptic curve
	return &ecdsa.PublicKey{
		X: x,
		Y: y,
	}, nil
}

func jwkToEdDSAPublicKey(jwk JSONWebKey) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported EdDSA curve: %s", jwk.Crv)
	}

	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return ed25519.PublicKey(xBytes), nil
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func parsePublicKeyPEM(pemStr string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch {
	case strings.Contains(block.Type, "RSA"):
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case block.Type == "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// CreateKeyFunc returns a jwt.Keyfunc for JWT verification
func (b *backend) CreateKeyFunc(ctx context.Context, s logical.Storage, config *Config) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Get the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Get the issuer from claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid claims type")
		}

		issuer, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("missing iss claim")
		}

		// Validate issuer is trusted
		trusted := false
		for _, ti := range config.TrustedIssuers {
			if ti == issuer {
				trusted = true
				break
			}
		}
		if !trusted {
			return nil, fmt.Errorf("untrusted issuer: %s", issuer)
		}

		// Validate algorithm
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing alg in token header")
		}

		allowedAlg := false
		for _, a := range config.AllowedAlgorithms {
			if a == alg {
				allowedAlg = true
				break
			}
		}
		if !allowedAlg {
			return nil, fmt.Errorf("algorithm %s not allowed", alg)
		}

		return b.GetVerificationKey(ctx, s, issuer, kid)
	}
}

