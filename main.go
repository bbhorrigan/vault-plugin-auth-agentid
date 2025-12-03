package main

import (
	"log"
	"os"

	"github.com/bbhorrigan/vault-plugin-auth-agentid/backend"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	}); err != nil {
		log.Printf("plugin shutting down: %v", err)
		os.Exit(1)
	}
}
