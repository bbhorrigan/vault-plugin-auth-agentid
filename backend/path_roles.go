package backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesStoragePrefix = "roles/"
)

// RoleConfig holds configuration for a role
type RoleConfig struct {
	// Name is the role name
	Name string `json:"name"`

	// BoundSubjects is a list of allowed subject (sub) claim values
	BoundSubjects []string `json:"bound_subjects,omitempty"`

	// BoundIssuers restricts the role to specific issuers
	BoundIssuers []string `json:"bound_issuers,omitempty"`

	// BoundAudiences is a list of allowed audience claim values
	BoundAudiences []string `json:"bound_audiences,omitempty"`

	// BoundClaims is a map of claim name to required values
	// Supports exact match and glob patterns (using * as wildcard)
	BoundClaims map[string][]string `json:"bound_claims,omitempty"`

	// BoundAgentIDs is a list of allowed agent_id claim values
	BoundAgentIDs []string `json:"bound_agent_ids,omitempty"`

	// AllowedIntents restricts which intents are allowed for this role
	AllowedIntents []string `json:"allowed_intents,omitempty"`

	// TokenPolicies is a list of policies to attach to the token
	TokenPolicies []string `json:"token_policies,omitempty"`

	// TokenTTL is the TTL for tokens issued via this role (in seconds)
	TokenTTL int `json:"token_ttl,omitempty"`

	// TokenMaxTTL is the maximum TTL for tokens issued via this role (in seconds)
	TokenMaxTTL int `json:"token_max_ttl,omitempty"`

	// TokenNumUses is the maximum number of uses for the token
	TokenNumUses int `json:"token_num_uses,omitempty"`
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			"bound_subjects": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed subject (sub) claim values. If set, the token's sub claim must match one of these.",
			},
			"bound_issuers": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed issuers for this role. If set, restricts which issuers can use this role.",
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed audience claim values. If set, the token must have a matching audience.",
			},
			"bound_claims": {
				Type:        framework.TypeKVPairs,
				Description: "Map of claims to required values. Values can use * as a wildcard. Multiple values per claim are comma-separated.",
			},
			"bound_agent_ids": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed agent_id claim values.",
			},
			"allowed_intents": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed intent values. If set, the token's intent must match one of these.",
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies to attach to tokens issued via this role.",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "TTL for tokens issued via this role.",
			},
			"token_max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum TTL for tokens issued via this role.",
			},
			"token_num_uses": {
				Type:        framework.TypeInt,
				Description: "Maximum number of uses for tokens issued via this role.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
				Summary:  "Read a role configuration",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
				Summary:  "Create a new role",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
				Summary:  "Update an existing role",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
				Summary:  "Delete a role",
			},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    "Manage roles for agent authentication",
		HelpDescription: "Roles define authentication constraints and token parameters for agents. When an agent authenticates with a role, the token's claims are validated against the role's bound claims.",
	}
}

func pathRolesList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRolesList,
				Summary:  "List all configured roles",
			},
		},
		HelpSynopsis: "List all configured roles",
	}
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"name":             role.Name,
		"bound_subjects":   role.BoundSubjects,
		"bound_issuers":    role.BoundIssuers,
		"bound_audiences":  role.BoundAudiences,
		"bound_claims":     role.BoundClaims,
		"bound_agent_ids":  role.BoundAgentIDs,
		"allowed_intents":  role.AllowedIntents,
		"token_policies":   role.TokenPolicies,
		"token_ttl":        role.TokenTTL,
		"token_max_ttl":    role.TokenMaxTTL,
		"token_num_uses":   role.TokenNumUses,
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &RoleConfig{Name: name}
	}

	if boundSubjects, ok := d.GetOk("bound_subjects"); ok {
		role.BoundSubjects = boundSubjects.([]string)
	}

	if boundIssuers, ok := d.GetOk("bound_issuers"); ok {
		role.BoundIssuers = boundIssuers.([]string)
	}

	if boundAudiences, ok := d.GetOk("bound_audiences"); ok {
		role.BoundAudiences = boundAudiences.([]string)
	}

	if boundClaims, ok := d.GetOk("bound_claims"); ok {
		// Convert map[string]string to map[string][]string
		claimsMap := boundClaims.(map[string]string)
		role.BoundClaims = make(map[string][]string)
		for k, v := range claimsMap {
			// Support comma-separated values
			role.BoundClaims[k] = strings.Split(v, ",")
		}
	}

	if boundAgentIDs, ok := d.GetOk("bound_agent_ids"); ok {
		role.BoundAgentIDs = boundAgentIDs.([]string)
	}

	if allowedIntents, ok := d.GetOk("allowed_intents"); ok {
		role.AllowedIntents = allowedIntents.([]string)
	}

	if tokenPolicies, ok := d.GetOk("token_policies"); ok {
		role.TokenPolicies = tokenPolicies.([]string)
	}

	if tokenTTL, ok := d.GetOk("token_ttl"); ok {
		role.TokenTTL = tokenTTL.(int)
	}

	if tokenMaxTTL, ok := d.GetOk("token_max_ttl"); ok {
		role.TokenMaxTTL = tokenMaxTTL.(int)
	}

	if tokenNumUses, ok := d.GetOk("token_num_uses"); ok {
		role.TokenNumUses = tokenNumUses.(int)
	}

	// Validate TTLs
	if role.TokenTTL > 0 && role.TokenMaxTTL > 0 && role.TokenTTL > role.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl cannot exceed token_max_ttl"), nil
	}

	if err := b.saveRole(ctx, req.Storage, role); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := req.Storage.Delete(ctx, rolesStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("failed to delete role: %w", err)
	}

	return nil, nil
}

func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolesStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*RoleConfig, error) {
	entry, err := s.Get(ctx, rolesStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var role RoleConfig
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("failed to decode role: %w", err)
	}

	return &role, nil
}

func (b *backend) saveRole(ctx context.Context, s logical.Storage, role *RoleConfig) error {
	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+role.Name, role)
	if err != nil {
		return fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to save role: %w", err)
	}

	return nil
}

// validateAgainstRole checks if the claims satisfy the role's bound claims
func (b *backend) validateAgainstRole(role *RoleConfig, claims *AgentClaims) error {
	// Validate bound subjects
	if len(role.BoundSubjects) > 0 {
		if !stringInSlice(claims.Subject, role.BoundSubjects) {
			return fmt.Errorf("subject %q not allowed by role", claims.Subject)
		}
	}

	// Validate bound issuers
	if len(role.BoundIssuers) > 0 {
		if !stringInSlice(claims.Issuer, role.BoundIssuers) {
			return fmt.Errorf("issuer %q not allowed by role", claims.Issuer)
		}
	}

	// Validate bound audiences
	if len(role.BoundAudiences) > 0 {
		matched := false
		for _, aud := range claims.Audience {
			if stringInSlice(aud, role.BoundAudiences) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("audience not allowed by role")
		}
	}

	// Validate bound agent IDs
	if len(role.BoundAgentIDs) > 0 {
		if !stringInSlice(claims.AgentID, role.BoundAgentIDs) {
			return fmt.Errorf("agent_id %q not allowed by role", claims.AgentID)
		}
	}

	// Validate allowed intents
	if len(role.AllowedIntents) > 0 {
		if claims.Intent != "" && !stringInSlice(claims.Intent, role.AllowedIntents) {
			return fmt.Errorf("intent %q not allowed by role", claims.Intent)
		}
	}

	// Validate bound claims with glob pattern support
	for claimName, allowedValues := range role.BoundClaims {
		claimValue := b.getClaimValue(claims, claimName)
		if claimValue == "" {
			return fmt.Errorf("required claim %q not present in token", claimName)
		}

		matched := false
		for _, pattern := range allowedValues {
			if matchGlob(pattern, claimValue) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("claim %q value %q not allowed by role", claimName, claimValue)
		}
	}

	return nil
}

// getClaimValue extracts a claim value by name from the claims struct
func (b *backend) getClaimValue(claims *AgentClaims, name string) string {
	switch name {
	case "sub", "subject":
		return claims.Subject
	case "iss", "issuer":
		return claims.Issuer
	case "agent_id":
		return claims.AgentID
	case "intent":
		return claims.Intent
	case "tool_name":
		return claims.ToolName
	case "mcp_server":
		return claims.MCPServer
	case "req_hash":
		return claims.RequestHash
	default:
		return ""
	}
}

// stringInSlice checks if a string is in a slice
func stringInSlice(s string, slice []string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// matchGlob performs simple glob matching with * as wildcard
func matchGlob(pattern, value string) bool {
	// Exact match
	if pattern == value {
		return true
	}

	// Simple glob matching
	if !strings.Contains(pattern, "*") {
		return false
	}

	// Handle leading wildcard
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *substring* pattern
		return strings.Contains(value, strings.Trim(pattern, "*"))
	}

	if strings.HasPrefix(pattern, "*") {
		// *suffix pattern
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	}

	if strings.HasSuffix(pattern, "*") {
		// prefix* pattern
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}

	return false
}


