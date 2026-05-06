#!/usr/bin/env bash
# Colour Vault — Institution Deployment Script
# Colour Foundation — buildwithcolours@gmail.com
#
# Usage: npm run deploy:institution
# Or:    bash scripts/deploy-institution.sh

set -euo pipefail

COLOUR_VERSION="0.1.0"
MCP_PORT="${MCP_PORT:-3847}"
MCP_HOST="${MCP_HOST:-127.0.0.1}"
NETWORK="${NETWORK:-mainnet}"
CHAINS="${CHAINS:-ethereum,bitcoin}"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         Colour Vault MCP Deployment      ║"
echo "║         Version ${COLOUR_VERSION}                    ║"
echo "║         Colour Foundation                ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── Preflight Checks ────────────────────────────────────────────────────────

echo "→ Running preflight checks..."

if ! command -v node &>/dev/null; then
  echo "✗ Node.js not found. Install Node.js 20+: https://nodejs.org"
  exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
  echo "✗ Node.js 20+ required. Current: $(node --version)"
  exit 1
fi

if ! command -v cargo &>/dev/null; then
  echo "✗ Rust not found. Install: https://rustup.rs"
  exit 1
fi

echo "✓ Node.js $(node --version)"
echo "✓ Rust $(rustc --version)"

# ─── Build Core ──────────────────────────────────────────────────────────────

echo ""
echo "→ Building cryptographic core..."
cd core
cargo build --release --quiet
cd ..
echo "✓ Core built"

# ─── Install MCP Dependencies ─────────────────────────────────────────────────

echo ""
echo "→ Installing MCP server dependencies..."
cd mcp
npm ci --silent
npm run build --silent
cd ..
echo "✓ MCP server ready"

# ─── Generate Config ─────────────────────────────────────────────────────────

echo ""
echo "→ Generating configuration..."

INSTITUTION_NAME="${INSTITUTION_NAME:-$(hostname)}"

cat > colour.config.json << EOF
{
  "institution": "${INSTITUTION_NAME}",
  "network": "${NETWORK}",
  "chains": ["${CHAINS//,/\",\"}"],
  "mcp_host": "${MCP_HOST}",
  "mcp_port": ${MCP_PORT},
  "quantum_layer": "full",
  "log_level": "info",
  "colour_version": "${COLOUR_VERSION}"
}
EOF

echo "✓ Config written to colour.config.json"

# ─── Generate Compliance Bundle ───────────────────────────────────────────────

mkdir -p compliance

cat > compliance/deployment-declaration.json << EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "colour_version": "${COLOUR_VERSION}",
  "institution": "${INSTITUTION_NAME}",
  "deployment_type": "client_side_sovereign",
  "infrastructure": "institution_owned",
  "data_custody": {
    "user_private_keys": "none",
    "user_addresses": "none",
    "transaction_history": "none",
    "personal_data": "none",
    "note": "All data remains on user devices or within this institution's infrastructure"
  },
  "cryptographic_standards": {
    "key_encapsulation": "ML-KEM-1024 (NIST FIPS 203)",
    "signing_primary": "ML-DSA-87 (NIST FIPS 204)",
    "signing_secondary": "SPHINCS+-SHA2-256f (NIST FIPS 205)",
    "symmetric_primary": "AES-256-GCM",
    "symmetric_secondary": "ChaCha20-Poly1305",
    "key_derivation": "Argon2id (RFC 9106)",
    "secret_sharing": "Shamir 3-of-5"
  },
  "contact": "buildwithcolours@gmail.com"
}
EOF

echo "✓ Compliance bundle written to compliance/"

# ─── Start MCP Server ────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Colour Vault MCP server is ready"
echo "  Institution : ${INSTITUTION_NAME}"
echo "  Network     : ${NETWORK}"
echo "  Chains      : ${CHAINS}"
echo "  Endpoint    : http://${MCP_HOST}:${MCP_PORT}"
echo "  Health      : http://${MCP_HOST}:${MCP_PORT}/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Contact: buildwithcolours@gmail.com"
echo ""

INSTITUTION_NAME="${INSTITUTION_NAME}" \
NETWORK="${NETWORK}" \
CHAINS="${CHAINS}" \
MCP_HOST="${MCP_HOST}" \
MCP_PORT="${MCP_PORT}" \
  node mcp/dist/server.js
