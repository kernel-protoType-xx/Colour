#!/usr/bin/env bash
# Colour Vault — Sovereign Deployment Script
# For government and central bank deployments
# Colour Foundation — buildwithcolours@gmail.com

set -euo pipefail

COLOUR_VERSION="0.1.0"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     Colour Vault Sovereign Deployment    ║"
echo "║     Version ${COLOUR_VERSION}                        ║"
echo "║     Colour Foundation                    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  This deployment is for government and central bank use."
echo "  All operations occur on your infrastructure."
echo "  No data leaves your environment."
echo ""

# ─── Preflight ───────────────────────────────────────────────────────────────

echo "→ Running sovereign preflight checks..."

for cmd in node cargo openssl; do
  if ! command -v $cmd &>/dev/null; then
    echo "✗ Required: $cmd"
    exit 1
  fi
done

echo "✓ All prerequisites present"

# ─── Build ───────────────────────────────────────────────────────────────────

echo ""
echo "→ Building cryptographic core (release + audit profile)..."
cd core
cargo build --profile release-audit --quiet
cd ..
echo "✓ Audit-profile build complete (debug symbols retained for verification)"

# ─── Sovereign Config ────────────────────────────────────────────────────────

SOVEREIGN_NAME="${SOVEREIGN_NAME:-sovereign-deployment}"
NETWORK="${NETWORK:-mainnet}"

mkdir -p sovereign-package/{compliance,audit,config}

cat > sovereign-package/config/colour-sovereign.json << EOF
{
  "deployment": "sovereign",
  "institution": "${SOVEREIGN_NAME}",
  "colour_version": "${COLOUR_VERSION}",
  "network": "${NETWORK}",
  "chains": ["bitcoin", "ethereum", "solana"],
  "quantum_layer": "full",
  "mpc_enabled": true,
  "mpc_threshold": "3-of-5",
  "air_gap_signing": true,
  "audit_trail": true,
  "log_level": "info"
}
EOF

# ─── Architecture Attestation ─────────────────────────────────────────────────

cat > sovereign-package/compliance/architecture-attestation.json << EOF
{
  "document": "Colour Vault Architecture Attestation",
  "version": "${COLOUR_VERSION}",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "deployment": "${SOVEREIGN_NAME}",
  "attestations": {
    "zero_data_custody": "Colour Foundation operates no servers in the key management or signing path",
    "client_side_sovereign": "All cryptographic operations occur on infrastructure controlled by this institution",
    "open_source": "Complete source code available at https://github.com/colour-foundation/colour-vault",
    "nist_compliant": "All post-quantum algorithms are NIST-standardised (FIPS 203, 204, 205)",
    "reproducible_build": "Binary can be independently reproduced from source and verified"
  },
  "cryptographic_standards": {
    "FIPS_203": "ML-KEM-1024 — key encapsulation",
    "FIPS_204": "ML-DSA-87 — primary digital signatures",
    "FIPS_205": "SPHINCS+-SHA2-256f — hash-based secondary signatures",
    "RFC_9106": "Argon2id — key derivation",
    "RFC_8391": "XMSS-SHA512 — additional hash-based signing"
  },
  "contact": "buildwithcolours@gmail.com"
}
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sovereign package ready"
echo "  Location    : ./sovereign-package/"
echo "  Config      : sovereign-package/config/"
echo "  Compliance  : sovereign-package/compliance/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Contact: buildwithcolours@gmail.com"
echo ""
