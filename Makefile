# Plugin name
PLUGIN_NAME := vault-plugin-auth-agentid
PLUGIN_DIR := vault/plugins

# Go parameters
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED := 0

# Build directory
BUILD_DIR := bin

.PHONY: all build clean test fmt lint dev-setup register help

all: build

## build: Build the plugin binary
build:
	@echo "Building $(PLUGIN_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -o $(BUILD_DIR)/$(PLUGIN_NAME) .
	@echo "Built: $(BUILD_DIR)/$(PLUGIN_NAME)"

## build-all: Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-windows-amd64.exe .
	@echo "Done building for all platforms"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(PLUGIN_NAME)

## test: Run tests
test:
	@echo "Running tests..."
	go test -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## lint: Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

## dev-setup: Set up development Vault instance with plugin
dev-setup: build
	@echo "Setting up development Vault..."
	@mkdir -p $(PLUGIN_DIR)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) $(PLUGIN_DIR)/
	@echo "Plugin copied to $(PLUGIN_DIR)/"
	@echo ""
	@echo "To register the plugin, start Vault in dev mode with:"
	@echo "  vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR)"
	@echo ""
	@echo "Then register and enable the plugin:"
	@echo "  export VAULT_ADDR='http://127.0.0.1:8200'"
	@echo "  vault login root"
	@echo "  vault plugin register -sha256=$$(shasum -a 256 $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d ' ' -f1) auth $(PLUGIN_NAME)"
	@echo "  vault auth enable -path=agentid $(PLUGIN_NAME)"

## register: Register plugin with running Vault (requires VAULT_ADDR and VAULT_TOKEN)
register: build
	@echo "Registering plugin with Vault..."
	@SHA256=$$(shasum -a 256 $(BUILD_DIR)/$(PLUGIN_NAME) | cut -d ' ' -f1) && \
		vault plugin register -sha256=$$SHA256 auth $(PLUGIN_NAME)
	vault auth enable -path=agentid $(PLUGIN_NAME) || true
	@echo "Plugin registered and enabled at auth/agentid"

## example-config: Show example configuration commands
example-config:
	@echo "Example configuration commands:"
	@echo ""
	@echo "# Configure trusted issuers"
	@echo "vault write auth/agentid/config \\"
	@echo "    trusted_issuers=\"https://agent-provider.example.com\" \\"
	@echo "    required_audience=\"https://vault.example.com\" \\"
	@echo "    default_ttl=300 \\"
	@echo "    max_ttl=3600"
	@echo ""
	@echo "# Configure JWKS for an issuer (via URL)"
	@echo "vault write auth/agentid/jwks/agent-provider \\"
	@echo "    jwks_url=\"https://agent-provider.example.com/.well-known/jwks.json\""
	@echo ""
	@echo "# Or configure with a static public key"
	@echo "vault write auth/agentid/jwks/agent-provider \\"
	@echo "    kid=\"key-1\" \\"
	@echo "    public_key=@/path/to/public_key.pem"
	@echo ""
	@echo "# Login with a token"
	@echo "vault write auth/agentid/login token=\"<agent-jwt>\""

## help: Show this help
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

