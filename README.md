# vault-plugin-auth-agentid

A HashiCorp Vault auth plugin for verifying signed identity tokens from AI agents. Enables short-lived credentials based on trusted claims—no OAuth required. Ideal for secure AI agent workflows and decentralized identity in MCP environments.

## Features

- **JWT/TraT/SIOP Verification**: Full JWT validation with support for RS256, ES256, and EdDSA signing algorithms
- **JWKS Support**: Automatic key fetching and caching from JWKS endpoints
- **Role-Based Access Control**: Define roles with bound claims, allowed intents, and custom policies
- **Intent-Based Policies**: Map agent intents (read, write, code, etc.) to Vault policies
- **DID Support**: Works with Decentralized Identifiers (e.g., `did:web:agent.example.com`)
- **MCP Integration**: Metadata support for MCP server and tool tracking
- **Short-Lived Credentials**: Configurable TTLs for secure, time-bound access
- **Security Hardening**: HTTPS enforcement for JWKS, configurable clock skew tolerance, TLS 1.2+

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
| `jwks_cache_ttl` | JWKS cache TTL in seconds (0 to disable) | 300 (5 min) |
| `clock_skew_leeway` | Clock skew tolerance for exp/nbf validation | 60 (1 min) |
| `allow_insecure_jwks` | Allow HTTP JWKS URLs (dev only!) | false |
| `jwks_request_timeout` | Timeout for JWKS HTTP requests | 10 (sec) |

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

### 4. Configure Roles (Optional)

Roles provide more granular control over authentication:

```bash
vault write auth/agentid/role/my-agent-role \
    bound_issuers="https://agent-provider.example.com" \
    bound_subjects="did:web:myagent.example.com" \
    allowed_intents="read,write" \
    token_policies="agent-read,agent-write" \
    token_ttl=600 \
    token_max_ttl=3600
```

**Role Options:**

| Parameter | Description |
|-----------|-------------|
| `bound_subjects` | Allowed subject (sub) claim values |
| `bound_issuers` | Allowed issuers for this role |
| `bound_audiences` | Allowed audience claim values |
| `bound_claims` | Map of claim names to required values (supports glob `*`) |
| `bound_agent_ids` | Allowed agent_id claim values |
| `allowed_intents` | Allowed intent values |
| `token_policies` | Policies to attach to tokens |
| `token_ttl` | Token TTL for this role |
| `token_max_ttl` | Max token TTL for this role |
| `token_num_uses` | Max uses for tokens from this role |

### 5. List Roles

```bash
vault list auth/agentid/role/
```

## Authentication

### Login with Agent Token

```bash
vault write auth/agentid/login token="<signed-jwt>"
```

### Login with Role

When using a role, additional claim validation is performed:

```bash
vault write auth/agentid/login token="<signed-jwt>" role="my-agent-role"
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
| `auth/agentid/role/:name` | GET, POST, DELETE | Manage authentication roles |
| `auth/agentid/role` | LIST | List configured roles |

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

# Show version
make version
```

### Docker Development

The easiest way to develop and test is with Docker:

```bash
# Build and start the development environment
make docker-up

# View logs
make docker-logs

# Stop the environment
make docker-down
```

This starts Vault in dev mode with the plugin already registered. Connect with:

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
vault read auth/agentid/config
```

### Generating Test Tokens

Use the helper script to generate test JWTs:

```bash
./scripts/generate-test-token.sh "https://issuer.example.com" "did:web:agent.example.com" "read"
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
7. **Use roles** for fine-grained access control with bound claims

## Troubleshooting

### Common Errors

#### "auth method not configured"

The plugin hasn't been configured yet. Configure trusted issuers:

```bash
vault write auth/agentid/config trusted_issuers="https://your-issuer.com"
```

#### "invalid token: untrusted issuer"

The token's `iss` claim doesn't match any configured trusted issuer. Check:

```bash
vault read auth/agentid/config
```

Ensure the issuer in your token exactly matches one of the `trusted_issuers`.

#### "invalid token: token has expired"

The token's `exp` claim is in the past. Tokens must be fresh. If you're seeing this with valid tokens, check:

1. Clock synchronization between your token issuer and Vault server
2. Increase `clock_skew_leeway` if needed:
   ```bash
   vault write auth/agentid/config clock_skew_leeway=120
   ```

#### "invalid token: key with kid X not found in JWKS"

The key ID in the token header doesn't match any key in the JWKS. Check:

1. The `kid` in your token header matches a key in your JWKS
2. If using a JWKS URL, the cache might be stale. The default cache TTL is 5 minutes.
3. Verify JWKS is accessible: `curl -s <jwks_url>`

#### "jwks_url must use HTTPS"

For security, JWKS URLs must use HTTPS. For development only:

```bash
vault write auth/agentid/config allow_insecure_jwks=true
```

**Warning:** Never enable `allow_insecure_jwks` in production!

#### "role validation failed: intent X not allowed by role"

The token's intent doesn't match the role's `allowed_intents`. Check:

```bash
vault read auth/agentid/role/your-role
```

#### "algorithm X not allowed"

The token was signed with an algorithm not in `allowed_algorithms`. Check your config:

```bash
vault read auth/agentid/config
```

### Debugging Tips

1. **Enable debug logging** in Vault to see detailed auth attempts:
   ```bash
   vault server -dev -log-level=debug
   ```

2. **Decode your JWT** to inspect claims:
   ```bash
   # Decode the payload (middle part of JWT)
   echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
   ```

3. **Check JWKS configuration**:
   ```bash
   vault list auth/agentid/jwks/
   vault read auth/agentid/jwks/<issuer-name>
   ```

4. **Verify the public key matches**:
   ```bash
   # Extract the public key from your JWKS and compare with the signing key
   ```

### Getting Help

If you're still having issues:

1. Check the [GitHub Issues](https://github.com/bbhorrigan/vault-plugin-auth-agentid/issues)
2. Enable debug logging and capture the full error message
3. Verify your JWT claims match the expected format

## License

See [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please read the [SECURITY.md](SECURITY.md) for security-related contributions.

See [CHANGELOG.md](CHANGELOG.md) for version history.
