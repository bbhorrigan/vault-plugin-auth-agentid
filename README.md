# vault-plugin-auth-agentid

A HashiCorp Vault auth plugin for verifying signed identity tokens from AI agents. Enables short-lived credentials based on trusted claims—no OAuth required. Ideal for secure AI agent workflows and decentralized identity in MCP environments.

## Features

- **JWT/TraT/SIOP Verification**: Full JWT validation with support for RS256, ES256, and EdDSA signing algorithms
- **JWKS Support**: Automatic key fetching and caching from JWKS endpoints
- **Intent-Based Policies**: Map agent intents (read, write, code, etc.) to Vault policies
- **DID Support**: Works with Decentralized Identifiers (e.g., `did:web:agent.example.com`)
- **MCP Integration**: Metadata support for MCP server and tool tracking
- **Short-Lived Credentials**: Configurable TTLs for secure, time-bound access

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/bbhorrigan/vault-plugin-auth-agentid.git
cd vault-plugin-auth-agentid

# Build the plugin
make build

# Or build for all platforms
make build-all
```

### Registering with Vault

```bash
# Start Vault in dev mode with plugin directory
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
vault login root

# Calculate SHA256 and register
SHA256=$(shasum -a 256 bin/vault-plugin-auth-agentid | cut -d ' ' -f1)
vault plugin register -sha256=$SHA256 auth vault-plugin-auth-agentid

# Enable the auth method
vault auth enable -path=agentid vault-plugin-auth-agentid
```

## Configuration

### 1. Configure Trusted Issuers

```bash
vault write auth/agentid/config \
    trusted_issuers="https://agent-provider.example.com,https://another-issuer.com" \
    required_audience="https://vault.example.com" \
    default_ttl=300 \
    max_ttl=3600 \
    allowed_algorithms="RS256,ES256,EdDSA"
```

**Configuration Options:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `trusted_issuers` | Comma-separated list of trusted JWT issuers | Required |
| `required_audience` | Expected audience claim in tokens | Optional |
| `default_ttl` | Default token TTL in seconds | 300 (5 min) |
| `max_ttl` | Maximum token TTL in seconds | 3600 (1 hr) |
| `allowed_algorithms` | Allowed signing algorithms | RS256,ES256,EdDSA |

### 2. Configure JWKS for Each Issuer

**Option A: JWKS URL (recommended)**

```bash
vault write auth/agentid/jwks/agent-provider \
    jwks_url="https://agent-provider.example.com/.well-known/jwks.json"
```

**Option B: Static Public Key**

```bash
vault write auth/agentid/jwks/agent-provider \
    kid="key-2024" \
    public_key=@/path/to/public_key.pem
```

### 3. List Configured Issuers

```bash
vault list auth/agentid/jwks/
```

## Authentication

### Login with Agent Token

```bash
vault write auth/agentid/login token="<signed-jwt>"
```

### Expected Token Claims

The plugin expects JWTs with the following structure:

```json
{
  "iss": "https://agent-provider.example.com",
  "sub": "did:web:myagent.example.com",
  "aud": "https://vault.example.com",
  "exp": 1699999999,
  "iat": 1699999900,
  "agent_id": "agent-123",
  "intent": "read",
  "scope": ["secrets:read", "kv:list"],
  "tool_name": "vault-reader",
  "mcp_server": "mcp.example.com",
  "req_hash": "sha256:abcdef..."
}
```

**Claim Descriptions:**

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | Token issuer (must be in `trusted_issuers`) |
| `sub` | Yes* | Subject identifier (agent DID or ID) |
| `aud` | If configured | Audience (must match `required_audience`) |
| `exp` | Yes | Expiration time |
| `agent_id` | Yes* | Alternative agent identifier |
| `intent` | No | Agent's declared intent (maps to policies) |
| `scope` | No | Requested scopes (map to `scope-*` policies) |
| `tool_name` | No | MCP tool being accessed |
| `mcp_server` | No | Target MCP server |
| `req_hash` | No | Request hash for TraT tokens |

*At least one of `sub`, `agent_id`, or `agent_did` is required.

### Intent-to-Policy Mapping

The plugin automatically maps intents to policies:

| Intent | Assigned Policy |
|--------|-----------------|
| `read`, `query` | `agent-read` |
| `write`, `update`, `create` | `agent-write` |
| `admin`, `manage` | `agent-admin` |
| `refactor`, `code` | `agent-code` |

Scopes in the token (e.g., `["secrets:read"]`) are mapped to policies prefixed with `scope-` (e.g., `scope-secrets:read`).

## API Reference

### Paths

| Path | Methods | Description |
|------|---------|-------------|
| `auth/agentid/login` | POST | Authenticate with agent token |
| `auth/agentid/config` | GET, POST, DELETE | Manage plugin configuration |
| `auth/agentid/jwks/:issuer` | GET, POST, DELETE | Manage JWKS for issuers |
| `auth/agentid/jwks` | LIST | List configured issuers |

## Example Policies

Create policies to assign to authenticated agents:

```hcl
# agent-read.hcl
path "secret/data/agents/*" {
  capabilities = ["read", "list"]
}

# agent-write.hcl
path "secret/data/agents/*" {
  capabilities = ["create", "update", "read", "list"]
}

# agent-code.hcl
path "secret/data/code/*" {
  capabilities = ["read", "list"]
}
path "transit/encrypt/code-signing" {
  capabilities = ["update"]
}
```

## Development

```bash
# Format code
make fmt

# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Set up dev environment
make dev-setup
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Client                           │
│                  (MCP Tool / AI Agent)                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ POST auth/agentid/login
                              │ { token: "<JWT>" }
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Vault Server                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              vault-plugin-auth-agentid                 │  │
│  │                                                        │  │
│  │  1. Parse JWT header (alg, kid)                       │  │
│  │  2. Extract issuer from claims                        │  │
│  │  3. Validate issuer is trusted                        │  │
│  │  4. Fetch public key (JWKS URL or static)            │  │
│  │  5. Verify signature                                  │  │
│  │  6. Validate claims (exp, aud, etc.)                 │  │
│  │  7. Map intent/scope to policies                      │  │
│  │  8. Issue Vault token                                 │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Response: { auth: { client_token: "..." } }
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Agent uses Vault token                     │
│              to access secrets, transit, etc.                │
└─────────────────────────────────────────────────────────────┘
```

## Security Considerations

1. **Always use HTTPS** for JWKS URLs in production
2. **Rotate keys regularly** and ensure JWKS endpoints reflect current keys
3. **Set appropriate TTLs** - shorter is more secure
4. **Limit trusted issuers** to only those you control or explicitly trust
5. **Use required_audience** to prevent token reuse across services
6. **Monitor auth logs** for failed authentication attempts

## License

See [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please read the [SECURITY.md](SECURITY.md) for security-related contributions.
