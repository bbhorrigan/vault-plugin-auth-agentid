package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the framework.Backend and holds plugin state
type backend struct {
	*framework.Backend
}

// Factory is required by plugin.Serve and returns a logical.Backend implementation.
// This is the entry point for the Vault plugin system.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help: `
The Agent Identity auth method allows authentication using signed identity tokens
from AI agents. It supports JWT, Transaction Tokens (TraTs), and Self-Issued 
OpenID Provider (SIOP) tokens.

This plugin verifies tokens against configured trusted issuers and their JWKS
(JSON Web Key Sets), then issues short-lived Vault tokens with appropriate
policies based on the agent's identity and declared intent.

Use cases:
  - Secure AI agent workflows in MCP environments
  - Decentralized identity verification for autonomous agents
  - Intent-based access control for agent operations
  - Short-lived credential issuance for agent tasks

Configuration:
  1. Configure trusted issuers:     vault write auth/agentid/config trusted_issuers="issuer1,issuer2"
  2. Add JWKS for each issuer:      vault write auth/agentid/jwks/issuer1 jwks_url="https://..."
  3. Authenticate:                   vault write auth/agentid/login token="<signed-jwt>"
`,
		BackendType: logical.TypeCredential,
		AuthRenew:   b.authRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathConfig(b),
				pathJWKS(b),
				pathJWKSList(b),
			},
		),
	}

	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// authRenew handles token renewal requests
func (b *backend) authRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, nil
	}

	// Get configuration for TTL bounds
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Use configured TTLs or defaults
	ttl := req.Auth.TTL
	maxTTL := req.Auth.MaxTTL

	if config != nil {
		if config.DefaultTTL > 0 {
			ttl = time.Duration(config.DefaultTTL) * time.Second
		}
		if config.MaxTTL > 0 {
			maxTTL = time.Duration(config.MaxTTL) * time.Second
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = ttl
	resp.Auth.MaxTTL = maxTTL

	return resp, nil
}
