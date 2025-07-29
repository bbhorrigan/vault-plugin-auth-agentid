package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		Backend: &framework.Backend{
			Help: "MCP agent-auth plugin",
			Paths: framework.PathAppend(
				loginPaths(),
			),
			BackendType: logical.TypeLogical,
		},
	}
	if err := b.Setup(conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}
