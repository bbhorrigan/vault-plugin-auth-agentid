#!/bin/bash
#
# End-to-end test script for vault-plugin-auth-agentid
#
# Prerequisites:
#   - Vault CLI installed
#   - openssl installed
#   - jq installed (optional, for pretty output)
#
# Usage:
#   ./scripts/test-auth-flow.sh
#

set -e

echo "============================================"
echo "vault-plugin-auth-agentid E2E Test"
echo "============================================"
echo ""

# Check prerequisites
command -v vault >/dev/null 2>&1 || { echo "Error: vault CLI is required"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl is required"; exit 1; }

# Configuration
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
ISSUER="https://test-issuer.example.com"
KID="test-key-$(date +%s)"

export VAULT_ADDR
export VAULT_TOKEN

echo "Using Vault at: $VAULT_ADDR"
echo ""

# Check Vault status
echo "1. Checking Vault status..."
if ! vault status >/dev/null 2>&1; then
    echo "Error: Cannot connect to Vault at $VAULT_ADDR"
    echo "Make sure Vault is running (e.g., 'make docker-up' or 'vault server -dev')"
    exit 1
fi
echo "   Vault is running ✓"
echo ""

# Generate EC key pair
echo "2. Generating EC P-256 key pair..."
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/private.pem" 2>/dev/null
openssl ec -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem" 2>/dev/null
echo "   Key pair generated ✓"
echo ""

# Check if plugin is enabled
echo "3. Checking plugin status..."
if vault auth list 2>/dev/null | grep -q "agentid/"; then
    echo "   Plugin already enabled ✓"
else
    echo "   Enabling plugin..."
    
    # Try to register and enable the plugin
    if [ -f "bin/vault-plugin-auth-agentid" ]; then
        SHA256=$(sha256sum bin/vault-plugin-auth-agentid 2>/dev/null | cut -d ' ' -f1 || shasum -a 256 bin/vault-plugin-auth-agentid | cut -d ' ' -f1)
        vault plugin register -sha256=$SHA256 auth vault-plugin-auth-agentid 2>/dev/null || true
    fi
    
    vault auth enable -path=agentid vault-plugin-auth-agentid 2>/dev/null || {
        echo "   Error: Could not enable plugin"
        echo "   Make sure the plugin binary is in Vault's plugin directory"
        exit 1
    }
    echo "   Plugin enabled ✓"
fi
echo ""

# Configure the plugin
echo "4. Configuring plugin..."
vault write auth/agentid/config \
    trusted_issuers="$ISSUER" \
    allowed_algorithms="ES256" \
    allow_insecure_jwks=true \
    clock_skew_leeway=60 >/dev/null
echo "   Configuration saved ✓"
echo ""

# Add the public key
echo "5. Adding public key..."
vault write auth/agentid/jwks/test-issuer \
    kid="$KID" \
    public_key=@"$TMPDIR/public.pem" >/dev/null
echo "   Public key added with kid=$KID ✓"
echo ""

# Create a test role
echo "6. Creating test role..."
vault write auth/agentid/role/test-role \
    bound_issuers="$ISSUER" \
    allowed_intents="read,write" \
    token_policies="default" \
    token_ttl=600 >/dev/null
echo "   Role 'test-role' created ✓"
echo ""

# Generate JWT
echo "7. Generating test JWT..."
NOW=$(date +%s)
EXP=$((NOW + 3600))

# Create header
HEADER=$(echo -n '{"alg":"ES256","typ":"JWT","kid":"'"$KID"'"}' | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')

# Create payload
PAYLOAD=$(echo -n '{
  "iss": "'"$ISSUER"'",
  "sub": "did:web:test-agent.example.com",
  "aud": ["https://vault.example.com"],
  "exp": '"$EXP"',
  "iat": '"$NOW"',
  "agent_id": "test-agent-123",
  "intent": "read",
  "tool_name": "test-tool"
}' | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')

# Create signature
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -sign "$TMPDIR/private.pem" | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')

JWT="$HEADER.$PAYLOAD.$SIGNATURE"
echo "   JWT generated ✓"
echo ""

# Test login without role
echo "8. Testing login (without role)..."
RESULT=$(vault write -format=json auth/agentid/login token="$JWT" 2>&1) || {
    echo "   Login failed!"
    echo "$RESULT"
    exit 1
}

CLIENT_TOKEN=$(echo "$RESULT" | grep -o '"client_token":"[^"]*"' | cut -d'"' -f4 || echo "")
if [ -n "$CLIENT_TOKEN" ]; then
    echo "   Login successful ✓"
    echo "   Client Token: ${CLIENT_TOKEN:0:20}..."
else
    echo "   Login succeeded but couldn't parse token"
fi
echo ""

# Test login with role
echo "9. Testing login (with role)..."
RESULT=$(vault write -format=json auth/agentid/login token="$JWT" role="test-role" 2>&1) || {
    echo "   Login with role failed!"
    echo "$RESULT"
    exit 1
}
echo "   Login with role successful ✓"
echo ""

# Test with wrong intent (should fail)
echo "10. Testing role validation (should fail with wrong intent)..."
PAYLOAD_BAD=$(echo -n '{
  "iss": "'"$ISSUER"'",
  "sub": "did:web:test-agent.example.com",
  "exp": '"$EXP"',
  "iat": '"$NOW"',
  "agent_id": "test-agent-123",
  "intent": "admin"
}' | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')

SIGNATURE_BAD=$(echo -n "$HEADER.$PAYLOAD_BAD" | openssl dgst -sha256 -sign "$TMPDIR/private.pem" | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')
JWT_BAD="$HEADER.$PAYLOAD_BAD.$SIGNATURE_BAD"

if vault write auth/agentid/login token="$JWT_BAD" role="test-role" 2>/dev/null; then
    echo "   ERROR: Should have failed but succeeded!"
    exit 1
else
    echo "   Correctly rejected (intent 'admin' not allowed) ✓"
fi
echo ""

# Show current configuration
echo "============================================"
echo "Current Configuration"
echo "============================================"
echo ""
echo "Config:"
vault read auth/agentid/config 2>/dev/null || echo "  (unable to read)"
echo ""
echo "JWKS Issuers:"
vault list auth/agentid/jwks/ 2>/dev/null || echo "  (none)"
echo ""
echo "Roles:"
vault list auth/agentid/role/ 2>/dev/null || echo "  (none)"
echo ""

echo "============================================"
echo "All tests passed! ✓"
echo "============================================"
echo ""
echo "The plugin is working correctly. You can now:"
echo "  1. Add your real issuer: vault write auth/agentid/config trusted_issuers=..."
echo "  2. Configure JWKS: vault write auth/agentid/jwks/my-issuer jwks_url=..."
echo "  3. Create roles: vault write auth/agentid/role/my-role ..."
echo ""

