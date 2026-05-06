# Changelog

All notable changes to Colour Vault are documented here.

Format: [Semantic Versioning](https://semver.org)

---

## [0.1.0] — 2025

### Added

- Core Rust cryptographic library with 16-layer security model
- ML-KEM-1024 key encapsulation (FIPS 203)
- ML-DSA-87 digital signatures (FIPS 204)
- SPHINCS+-SHA2-256f hash-based signatures (FIPS 205)
- AES-256-GCM + ChaCha20-Poly1305 double encryption
- Argon2id key derivation (RFC 9106)
- Shamir Secret Sharing 3-of-5 recovery
- Anti-replay nonce registry with timestamp binding
- Automatic annual key rotation
- Wallet provenance gate (bech32 Bitcoin, EIP-55 Ethereum, base58 Solana)
- Multichain support: Bitcoin, Ethereum, Solana
- Offline transaction signing
- Secure memory management with zeroize
- MCP server for institutional deployment (TypeScript)
- One-command institution deployment
- Auto-generated compliance bundle
- Full test suite: unit, integration, edge cases, failure modes
- GitHub Actions CI pipeline
- ARCHITECTURE.md full technical specification
- WHITEPAPER.md
- SECURITY.md with bug bounty programme
- CHARTER.md foundation governance document
- Apache 2.0 licence
