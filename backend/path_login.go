package backend

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func loginPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "login",
			Fields: map[string]*framework.FieldSchema{
				"token": {
					Type:        framework.TypeString,
					Description: "Signed identity token (e.g., TraT or SIOP)",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: handleLogin,
			},
			HelpSynopsis: "Login using an agent-signed token",
		},
	}
}

func handleLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)

	// TODO: Add real JWT verification (e.g., parse and validate TraT/SIOP claims)
	if token == "letmein" {
		// mock success
		resp := &logical.Response{
			Auth: &logical.Auth{
				Policies:    []string{"default"},
				DisplayName: "mcp-agent",
				Metadata: map[string]string{
					"mcp": "verified",
				},
			},
		}
		return resp, nil
	}

	return nil, logical.ErrPermissionDenied
}
