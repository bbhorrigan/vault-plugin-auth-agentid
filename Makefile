# Plugin name
PLUGIN_NAME := vault-plugin-auth-agentid
PLUGIN_DIR := vault/plugins

# Go parameters
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED := 0

# Build directory
BUILD_DIR := bin

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Linker flags for version info
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-X main.BuildTime=$(BUILD_TIME)

.PHONY: all build clean test fmt lint dev-setup register help docker docker-up docker-down version

all: build

## version: Show version information
version:
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

## build: Build the plugin binary
build:
	@echo "Building $(PLUGIN_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME) .
	@echo "Built: $(BUILD_DIR)/$(PLUGIN_NAME)"

## build-all: Build for multiple platforms
build-all:
	@echo "Building $(VERSION) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(PLUGIN_NAME)-windows-amd64.exe .
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
	@echo "# Create a role"
	@echo "vault write auth/agentid/role/my-role \\"
	@echo "    bound_issuers=\"https://agent-provider.example.com\" \\"
	@echo "    allowed_intents=\"read,write\" \\"
	@echo "    token_policies=\"my-policy\" \\"
	@echo "    token_ttl=600"
	@echo ""
	@echo "# Login with a token"
	@echo "vault write auth/agentid/login token=\"<agent-jwt>\""
	@echo ""
	@echo "# Login with a token and role"
	@echo "vault write auth/agentid/login token=\"<agent-jwt>\" role=\"my-role\""

## docker: Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(PLUGIN_NAME):$(VERSION) -t $(PLUGIN_NAME):latest .

## docker-up: Start development environment with Docker Compose
docker-up: docker
	@echo "Starting development environment..."
	docker-compose up -d
	@echo ""
	@echo "Vault is running at http://localhost:8200"
	@echo "Root token: root"
	@echo ""
	@echo "To interact with Vault:"
	@echo "  export VAULT_ADDR=http://localhost:8200"
	@echo "  export VAULT_TOKEN=root"

## docker-down: Stop development environment
docker-down:
	@echo "Stopping development environment..."
	docker-compose down -v

## docker-logs: Show logs from development environment
docker-logs:
	docker-compose logs -f vault

## help: Show this help
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

