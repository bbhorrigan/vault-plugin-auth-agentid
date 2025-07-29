package main

import (
    "context"
    "errors"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
    "time"
)

func pathLogin(b *MCPAuthBackend) *framework.Path {
    return &framework.Path{
        Pattern: "login",
        Fields: map[string]*framework.FieldSchema{
            "jwt": {
                Type:        framework.TypeString,
                Description: "The JWT or TraT token from the agent",
                Required:    true,
            },
        },
        Callbacks: map[logical.Operation]framework.OperationFunc{
            logical.CreateOperation: b.handleLogin,
        },
        HelpSynopsis:    "Agent login via token",
        HelpDescription: "Verifies agent token and returns a Vault token.",
    }
}

func (b *MCPAuthBackend) handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    token := d.Get("jwt").(string)

    // TODO: Replace with actual JWT or TraT validation
    if token == "" {
        return nil, errors.New("missing token")
    }

    // Mock claims
    entityAlias := "did:web:myagent.com"
    intent := "refactor"

    // TODO: Validate claims like aud, exp, sub, intent, etc.

    return &logical.Response{
        Auth: &logical.Auth{
            InternalData: map[string]interface{}{},
            DisplayName:  entityAlias,
            Policies:     []string{"default"},
            Metadata: map[string]string{
                "intent": intent,
                "agent":  entityAlias,
            },
            LeaseOptions: logical.LeaseOptions{
                TTL:       time.Minute,
                Renewable: true,
            },
        },
    }, nil
}
