#!/bin/bash
#
# Generate a test JWT for vault-plugin-auth-agentid
#
# This script generates an EC (P-256) key pair and a signed JWT
# that can be used for testing the plugin.
#
# Usage:
#   ./generate-test-token.sh [issuer] [subject] [intent]
#
# Example:
#   ./generate-test-token.sh "https://issuer.example.com" "did:web:agent.example.com" "read"
#

set -e

# Default values
ISSUER="${1:-https://test-issuer.example.com}"
SUBJECT="${2:-did:web:test-agent.example.com}"
INTENT="${3:-read}"
AGENT_ID="${4:-agent-$(date +%s)}"
KID="test-key-$(date +%s)"

# Check for required tools
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is required but not installed."
    exit 1
fi

# Create temporary directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Generate EC key pair
echo "Generating EC P-256 key pair..."
openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR/private.pem" 2>/dev/null
openssl ec -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem" 2>/dev/null

# Calculate timestamps
NOW=$(date +%s)
EXP=$((NOW + 3600))  # 1 hour from now
IAT=$NOW
NBF=$NOW

# Create JWT header
HEADER=$(echo -n '{"alg":"ES256","typ":"JWT","kid":"'"$KID"'"}' | openssl base64 -e | tr -d '\n=' | tr '+/' '-_')

# Create JWT payload
PAYLOAD=$(cat <<EOF | openssl base64 -e | tr -d '\n=' | tr '+/'  '-_'
{
  "iss": "$ISSUER",
  "sub": "$SUBJECT",
  "aud": ["https://vault.example.com"],
  "exp": $EXP,
  "iat": $IAT,
  "nbf": $NBF,
  "agent_id": "$AGENT_ID",
  "intent": "$INTENT",
  "scope": ["secrets:read"],
  "tool_name": "test-tool",
  "mcp_server": "mcp.example.com"
}
EOF
)

# Create signature
SIGNATURE_INPUT="$HEADER.$PAYLOAD"
echo -n "$SIGNATURE_INPUT" | openssl dgst -sha256 -sign "$TMPDIR/private.pem" | openssl base64 -e | tr -d '\n=' | tr '+/' '-_' > "$TMPDIR/signature"
SIGNATURE=$(cat "$TMPDIR/signature")

# Construct JWT
JWT="$HEADER.$PAYLOAD.$SIGNATURE"

echo ""
echo "============================================"
echo "Generated Test JWT"
echo "============================================"
echo ""
echo "Key ID (kid): $KID"
echo "Issuer:       $ISSUER"
echo "Subject:      $SUBJECT"
echo "Intent:       $INTENT"
echo "Agent ID:     $AGENT_ID"
echo "Expires:      $(date -d @$EXP 2>/dev/null || date -r $EXP)"
echo ""
echo "============================================"
echo "Public Key (PEM)"
echo "============================================"
cat "$TMPDIR/public.pem"
echo ""
echo "============================================"
echo "JWT Token"
echo "============================================"
echo "$JWT"
echo ""
echo "============================================"
echo "Vault Configuration Commands"
echo "============================================"
echo ""
echo "# 1. Configure the plugin with the issuer"
echo "vault write auth/agentid/config \\"
echo "    trusted_issuers=\"$ISSUER\" \\"
echo "    allowed_algorithms=\"ES256\""
echo ""
echo "# 2. Add the public key"
echo "vault write auth/agentid/jwks/test-issuer \\"
echo "    kid=\"$KID\" \\"
echo "    public_key=@$TMPDIR/public.pem"
echo ""
echo "# Or save the public key and use:"
cat "$TMPDIR/public.pem" > public_key.pem
echo "# Public key saved to: public_key.pem"
echo ""
echo "# 3. Test login"
echo "vault write auth/agentid/login token=\"$JWT\""
echo ""


