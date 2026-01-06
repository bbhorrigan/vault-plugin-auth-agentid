# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the plugin
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev') -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o vault-plugin-auth-agentid .

# Runtime stage
FROM hashicorp/vault:1.15

# Copy the plugin binary
COPY --from=builder /app/vault-plugin-auth-agentid /vault/plugins/vault-plugin-auth-agentid

# Set permissions
RUN chmod +x /vault/plugins/vault-plugin-auth-agentid

# Environment variables for dev mode
ENV VAULT_DEV_ROOT_TOKEN_ID=root
ENV VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
ENV VAULT_LOCAL_CONFIG='{"plugin_directory": "/vault/plugins", "log_level": "debug"}'

# Expose Vault port
EXPOSE 8200

# Start Vault in dev mode with plugin directory
ENTRYPOINT ["vault", "server", "-dev", "-dev-plugin-dir=/vault/plugins"]


