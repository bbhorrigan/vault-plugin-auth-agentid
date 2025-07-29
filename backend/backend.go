package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory is required by plugin.Serve and returns a logical.Backend implementation.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help: "Auth plugin for verifying signed identity tokens from agents (e.g. TraT, SIOP).",
		Paths: framework.PathAppend([]*framework.Path{
			// Add path handlers here (e.g., for login)
		}, []*framework.Path{}...),
		BackendType: logical.TypeCredential,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}
