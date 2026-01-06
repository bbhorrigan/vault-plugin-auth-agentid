package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// AgentClaims represents the expected claims in an agent identity token
type AgentClaims struct {
	jwt.RegisteredClaims

	// Agent-specific claims
	AgentID     string   `json:"agent_id,omitempty"`
	AgentDID    string   `json:"sub,omitempty"`        // DID of the agent (e.g., did:web:agent.example.com)
	Intent      string   `json:"intent,omitempty"`     // What the agent intends to do
	Scope       []string `json:"scope,omitempty"`      // Requested scopes/permissions
	RequestHash string   `json:"req_hash,omitempty"`   // Hash of the request (for TraTs)
	ToolName    string   `json:"tool_name,omitempty"`  // MCP tool being accessed
	MCPServer   string   `json:"mcp_server,omitempty"` // Target MCP server
}

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Signed identity token (JWT, TraT, or SIOP)",
				Required:    true,
			},
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to authenticate against (optional)",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Authenticate using an agent identity token",
			},
			// Support AliasLookahead for entity alias resolution
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.handleLogin,
			},
		},
		HelpSynopsis:    "Login using an agent-signed identity token",
		HelpDescription: "Authenticates an agent by verifying its signed identity token (JWT, TraT, or SIOP) and returns a Vault token with appropriate policies.",
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Log login attempt with request ID for tracing
	b.Backend.Logger().Debug("login attempt", "request_id", req.ID, "operation", req.Operation)

	tokenStr := d.Get("token").(string)
	if tokenStr == "" {
		b.Backend.Logger().Debug("login failed: missing token", "request_id", req.ID)
		return logical.ErrorResponse("missing required 'token' parameter"), nil
	}

	// Get optional role parameter
	roleName := ""
	if roleRaw, ok := d.GetOk("role"); ok {
		roleName = roleRaw.(string)
	}

	// Get configuration
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	if config == nil {
		b.Backend.Logger().Debug("login failed: not configured", "request_id", req.ID)
		return logical.ErrorResponse("auth method not configured - please configure trusted issuers first"), nil
	}

	if len(config.TrustedIssuers) == 0 {
		b.Backend.Logger().Debug("login failed: no trusted issuers", "request_id", req.ID)
		return logical.ErrorResponse("no trusted issuers configured"), nil
	}

	// Parse and validate the token
	claims, err := b.validateToken(ctx, req.Storage, config, tokenStr)
	if err != nil {
		b.Backend.Logger().Warn("token validation failed",
			"request_id", req.ID,
			"error", err,
		)
		return logical.ErrorResponse("invalid token: %s", err), nil
	}

	// If a role is specified, validate claims against role and use role settings
	var role *RoleConfig
	if roleName != "" {
		role, err = b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to get role: %w", err)
		}
		if role == nil {
			b.Backend.Logger().Debug("login failed: role not found", "request_id", req.ID, "role", roleName)
			return logical.ErrorResponse("role %q not found", roleName), nil
		}

		// Validate claims against role
		if err := b.validateAgainstRole(role, claims); err != nil {
			b.Backend.Logger().Warn("role validation failed",
				"request_id", req.ID,
				"role", roleName,
				"error", err,
			)
			return logical.ErrorResponse("role validation failed: %s", err), nil
		}
	}

	// Build the auth response
	auth := b.buildAuthResponse(config, claims)

	// Apply role-specific settings if a role was used
	if role != nil {
		auth.InternalData["role"] = role.Name

		// Override policies with role-specific policies if set
		if len(role.TokenPolicies) > 0 {
			auth.Policies = append([]string{"default"}, role.TokenPolicies...)
		}

		// Override TTLs with role-specific values if set
		if role.TokenTTL > 0 {
			auth.TTL = time.Duration(role.TokenTTL) * time.Second
		}
		if role.TokenMaxTTL > 0 {
			auth.MaxTTL = time.Duration(role.TokenMaxTTL) * time.Second
		}
		if role.TokenNumUses > 0 {
			auth.NumUses = role.TokenNumUses
		}

		// Add role to alias metadata
		auth.Alias.Metadata["role"] = role.Name
	}

	// Log successful authentication
	b.Backend.Logger().Info("login successful",
		"request_id", req.ID,
		"agent", auth.Alias.Name,
		"issuer", claims.Issuer,
		"intent", claims.Intent,
		"role", roleName,
		"policies", auth.Policies,
	)

	// For alias lookahead, just return the alias
	if req.Operation == logical.AliasLookaheadOperation {
		return &logical.Response{
			Auth: auth,
		}, nil
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) validateToken(ctx context.Context, s logical.Storage, config *Config, tokenStr string) (*AgentClaims, error) {
	// Create the key function for verification
	keyFunc := b.CreateKeyFunc(ctx, s, config)

	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenStr, &AgentClaims{}, keyFunc, jwt.WithValidMethods(config.AllowedAlgorithms))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*AgentClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Validate required claims
	if err := b.validateClaims(config, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (b *backend) validateClaims(config *Config, claims *AgentClaims) error {
	// Get clock skew leeway (default: 60 seconds)
	leeway := time.Duration(60) * time.Second
	if config.ClockSkewLeeway > 0 {
		leeway = time.Duration(config.ClockSkewLeeway) * time.Second
	}

	now := time.Now()

	// Validate expiration with clock skew leeway
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Add(leeway).Before(now) {
		return fmt.Errorf("token has expired")
	}

	// Validate not-before with clock skew leeway
	if claims.NotBefore != nil && claims.NotBefore.Time.Add(-leeway).After(now) {
		return fmt.Errorf("token is not yet valid")
	}

	// Validate audience if configured
	if config.RequiredAudience != "" {
		validAud := false
		for _, aud := range claims.Audience {
			if aud == config.RequiredAudience {
				validAud = true
				break
			}
		}
		if !validAud {
			return fmt.Errorf("invalid audience: expected %s", config.RequiredAudience)
		}
	}

	// Validate issuer is trusted (already done in keyFunc, but double-check)
	trusted := false
	for _, ti := range config.TrustedIssuers {
		if ti == claims.Issuer {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("untrusted issuer: %s", claims.Issuer)
	}

	// Require subject (agent identity)
	if claims.Subject == "" && claims.AgentDID == "" && claims.AgentID == "" {
		return fmt.Errorf("token must contain subject (sub), agent_id, or agent DID")
	}

	return nil
}

func (b *backend) buildAuthResponse(config *Config, claims *AgentClaims) *logical.Auth {
	// Determine the entity alias (unique identifier for the agent)
	entityAlias := claims.Subject
	if entityAlias == "" {
		entityAlias = claims.AgentDID
	}
	if entityAlias == "" {
		entityAlias = claims.AgentID
	}

	// Build display name
	displayName := entityAlias
	if claims.AgentID != "" && claims.AgentID != entityAlias {
		displayName = claims.AgentID
	}

	// Calculate TTL
	ttl := time.Duration(config.DefaultTTL) * time.Second
	maxTTL := time.Duration(config.MaxTTL) * time.Second

	// If token has shorter expiry, use that
	if claims.ExpiresAt != nil {
		tokenTTL := time.Until(claims.ExpiresAt.Time)
		if tokenTTL < ttl {
			ttl = tokenTTL
		}
	}

	// Build metadata from claims
	metadata := map[string]string{
		"issuer": claims.Issuer,
		"agent":  entityAlias,
	}

	if claims.Intent != "" {
		metadata["intent"] = claims.Intent
	}

	if claims.ToolName != "" {
		metadata["tool_name"] = claims.ToolName
	}

	if claims.MCPServer != "" {
		metadata["mcp_server"] = claims.MCPServer
	}

	if claims.RequestHash != "" {
		metadata["request_hash"] = claims.RequestHash
	}

	// Determine policies based on intent/scope
	policies := []string{"default"}

	// Map intents to policies (this can be extended with role configuration)
	if claims.Intent != "" {
		switch claims.Intent {
		case "read", "query":
			policies = append(policies, "agent-read")
		case "write", "update", "create":
			policies = append(policies, "agent-write")
		case "admin", "manage":
			policies = append(policies, "agent-admin")
		case "refactor", "code":
			policies = append(policies, "agent-code")
		}
	}

	// Add scope-based policies
	for _, scope := range claims.Scope {
		policies = append(policies, "scope-"+scope)
	}

	return &logical.Auth{
		InternalData: map[string]interface{}{
			"token_claims": claims,
		},
		DisplayName: displayName,
		Policies:    policies,
		Alias: &logical.Alias{
			Name: entityAlias,
			Metadata: map[string]string{
				"issuer": claims.Issuer,
			},
		},
		Metadata: metadata,
		LeaseOptions: logical.LeaseOptions{
			TTL:       ttl,
			MaxTTL:    maxTTL,
			Renewable: true,
		},
	}
}
