package main

import (
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/bbhorrigan/vault-plugin-auth-agentid/backend"

)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	})
}
