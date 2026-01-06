package main

import (
	"fmt"
	"log"
	"os"

	"github.com/bbhorrigan/vault-plugin-auth-agentid/backend"
	"github.com/hashicorp/vault/sdk/plugin"
)

// Version information - set via ldflags during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Handle version flag
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("vault-plugin-auth-agentid\n")
		fmt.Printf("  Version:    %s\n", Version)
		fmt.Printf("  Build Time: %s\n", BuildTime)
		fmt.Printf("  Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	// Log version on startup
	log.Printf("Starting vault-plugin-auth-agentid version=%s build_time=%s", Version, BuildTime)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	}); err != nil {
		log.Printf("plugin shutting down: %v", err)
		os.Exit(1)
	}
}
