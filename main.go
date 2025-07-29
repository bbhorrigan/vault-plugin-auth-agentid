package main

import (
	"github.com/hashicorp/vault/sdk/plugin"
	"vault-plugin-auth-mcp/backend"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	})
}
