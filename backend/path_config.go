package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// Config holds the plugin configuration
type Config struct {
	// TrustedIssuers is a list of allowed JWT issuers (iss claim)
	TrustedIssuers []string `json:"trusted_issuers"`

	// DefaultTTL is the default token TTL in seconds
	DefaultTTL int `json:"default_ttl"`

	// MaxTTL is the maximum token TTL in seconds
	MaxTTL int `json:"max_ttl"`

	// RequiredAudience is the expected audience claim
	RequiredAudience string `json:"required_audience"`

	// AllowedAlgorithms specifies which signing algorithms are permitted
	AllowedAlgorithms []string `json:"allowed_algorithms"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		TrustedIssuers:    []string{},
		DefaultTTL:        300,  // 5 minutes
		MaxTTL:            3600, // 1 hour
		RequiredAudience:  "",
		AllowedAlgorithms: []string{"RS256", "ES256", "EdDSA"},
	}
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"trusted_issuers": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of trusted JWT issuers (iss claim values)",
				Required:    false,
			},
			"default_ttl": {
				Type:        framework.TypeInt,
				Description: "Default TTL for issued tokens in seconds (default: 300)",
				Required:    false,
			},
			"max_ttl": {
				Type:        framework.TypeInt,
				Description: "Maximum TTL for issued tokens in seconds (default: 3600)",
				Required:    false,
			},
			"required_audience": {
				Type:        framework.TypeString,
				Description: "Required audience claim (aud) in the JWT",
				Required:    false,
			},
			"allowed_algorithms": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed signing algorithms (default: RS256,ES256,EdDSA)",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the current configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the auth plugin",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete the configuration",
			},
		},
		HelpSynopsis:    "Configure the agent identity auth plugin",
		HelpDescription: "Configure trusted issuers, TTLs, and other settings for agent authentication.",
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"trusted_issuers":    config.TrustedIssuers,
			"default_ttl":        config.DefaultTTL,
			"max_ttl":            config.MaxTTL,
			"required_audience":  config.RequiredAudience,
			"allowed_algorithms": config.AllowedAlgorithms,
		},
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = DefaultConfig()
	}

	if trustedIssuers, ok := d.GetOk("trusted_issuers"); ok {
		config.TrustedIssuers = trustedIssuers.([]string)
	}

	if defaultTTL, ok := d.GetOk("default_ttl"); ok {
		config.DefaultTTL = defaultTTL.(int)
	}

	if maxTTL, ok := d.GetOk("max_ttl"); ok {
		config.MaxTTL = maxTTL.(int)
	}

	if requiredAudience, ok := d.GetOk("required_audience"); ok {
		config.RequiredAudience = requiredAudience.(string)
	}

	if allowedAlgorithms, ok := d.GetOk("allowed_algorithms"); ok {
		config.AllowedAlgorithms = allowedAlgorithms.([]string)
	}

	// Validate configuration
	if config.DefaultTTL > config.MaxTTL {
		return logical.ErrorResponse("default_ttl cannot exceed max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	return nil, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("failed to delete config: %w", err)
	}
	return nil, nil
}

func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var config Config
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &config, nil
}

