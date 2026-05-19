# Colour — Architecture

This document describes the technical architecture of the Colour protocol suite, comprising two integrated systems:

- **Colour Vault** — post-quantum cryptographic vault for self-custody asset management
- **Colour Shield** — post-quantum package security layer for software supply chains

Colour Foundation — buildwithcolours@gmail.com
Audited by Cure53

---

## System Overview

```
┌─────────────────────────────────────────────────────┐
│                  COLOUR PROTOCOL                    │
│                                                     │
│  ┌─────────────────┐    ┌─────────────────────────┐ │
│  │  COLOUR VAULT   │    │     COLOUR SHIELD       │ │
│  │                 │    │                         │ │
│  │ Self-custody    │    │ Package security        │ │
│  │ Post-quantum    │    │ Supply chain protection │ │
│  │ Key management  │    │ Registry verification   │ │
│  └────────┬────────┘    └───────────┬─────────────┘ │
│           │                        │               │
│           └──────────┬─────────────┘               │
│                      │                             │
│           ┌──────────▼─────────────┐               │
│           │   COLOUR CORE (Rust)   │               │
│           │   ML-KEM-1024          │               │
│           │   ML-DSA-87            │               │
│           │   SPHINCS+-256         │               │
│           │   XMSS-SHA512          │               │
│           └────────────────────────┘               │
└─────────────────────────────────────────────────────┘
```

---

# PART 1 — COLOUR VAULT

## Overview

Colour Vault is a client-side sovereign cryptographic vault. It implements post-quantum resistant key generation, storage, and signing. No key material ever leaves the device that generated it. The Colour Foundation operates no servers in the signing or key management path.

---

## Threat Model

### What Colour Vault protects against

- Classical cryptographic attacks on key material (ECDSA, RSA)
- Quantum attacks via Shor's algorithm on elliptic curve keys
- Quantum attacks via Grover's algorithm on symmetric keys
- Memory disclosure attacks on key material at rest and in use
- Transaction replay attacks
- Supply chain attacks on the binary
- Single point of failure in key recovery

### What Colour Vault does not protect against

- Social engineering of the user
- Physical coercion of the user
- Compromise of the operating system kernel with root access
- Hardware vulnerabilities in the secure enclave itself
- Loss of all recovery shares simultaneously
- Bugs in the underlying NIST-standardised cryptographic libraries

---

## Security Layers

### Layer 1 — Post-Quantum Key Generation

Three independent NIST-standardised algorithms used simultaneously.

**ML-KEM-1024 (FIPS 203)** — Lattice-based key encapsulation. NIST Level 5. Used for key encapsulation and transport.

**ML-DSA-87 (FIPS 204)** — Lattice-based digital signature. NIST Level 5. Used for primary transaction signing.

**SPHINCS+-SHA2-256f (FIPS 205)** — Hash-based digital signature. NIST Level 5. Security assumption: SHA-256 collision resistance only — independent of lattice assumptions. Used for secondary signing.

Both ML-DSA and SPHINCS+ must verify for a transaction to be valid.

### Layer 2 — Hardware Secure Enclave

| Platform | Technology |
|---|---|
| iOS | Secure Enclave Processor |
| Android | StrongBox Keymaster / TEE fallback |
| Desktop | TPM 2.0 where available |

The application process never holds raw private key bytes.

### Layer 3 — Multi-Party Computation

Threshold signatures for institutional deployments. Minimum 2-of-3. Key never reconstructed in full. Mandatory for institutional deployments.

### Layer 4 — Symmetric Encryption at Rest

Double-encrypted vault data:
- Layer 4a: AES-256-GCM with Argon2id key derivation
- Layer 4b: ChaCha20-Poly1305 with independent Argon2id key

Ciphertext: ChaCha20-Poly1305( AES-256-GCM( plaintext ) )

Argon2id: 64 MiB memory, 3 iterations, 4 parallelism.

### Layer 5 — Shamir Secret Sharing (3-of-5)

5 shares generated. Any 3 reconstruct the secret. Losing 2 shares does not affect recoverability. Information-theoretic security below threshold.

### Layer 6 — Zero-Knowledge Proofs

zk-STARKs used to prove vault ownership without revealing key material. No trusted setup. Post-quantum safe.

### Layer 7 — Side-Channel Attack Mitigation

Constant-time operations via the subtle crate. Secret-independent memory access patterns throughout.

### Layer 8 — Secure Memory Management

All sensitive types implement Zeroize and ZeroizeOnDrop. Debug implementations output [REDACTED]. SecureBuffer wraps all temporary sensitive allocations.

### Layer 9 — Supply Chain Security

Reproducible deterministic builds. All dependencies pinned with cryptographic hashes. cargo audit and npm audit on every commit. GPG-signed releases.

### Layer 10 — Anti-Replay Protection

Every transaction contains a 32-byte random nonce, Unix timestamp (5 minute window), and chain ID binding. Nonce registry rejects any previously seen nonce.

### Layer 11 — Protocol Hardening

No legacy cipher fallback. Perfect Forward Secrecy per session. TLS 1.3 minimum for all MCP communications.

### Layer 12 — Formal Verification

Critical Rust paths verified using the Kani model checker. Key generation, encryption roundtrip, Shamir split/reconstruct, and nonce registry all verified.

### Layer 13 — Entropy Quality

OS CSPRNG as primary source. Optional QRNG mixing via BLAKE3. Entropy pool validated before key generation.

### Layer 14 — QKD-Compatible Design

Compatible with Quantum Key Distribution hardware at the key transport layer without protocol changes.

### Layer 15 — NTRU Prime

Second independent lattice scheme. Different construction from ML-KEM — mathematical breakthrough in one does not transfer to the other.

### Layer 16 — XMSS-SHA512

Third signing algorithm based entirely on SHA-512. No lattice mathematics. Standardised by NIST and IETF. Effective ~256-bit security against Grover's algorithm.

---

## Multichain Key Derivation

| Chain | Derivation Path | Signature Scheme |
|---|---|---|
| Bitcoin | m/44'/0'/0'/0/0 | secp256k1 (P2WPKH) |
| Ethereum | m/44'/60'/0'/0/0 | secp256k1 (EIP-155) |
| Solana | m/44'/501'/0'/0' | Ed25519 |

Post-quantum signatures apply at the vault protocol level.

---

## Key Rotation

Keys rotate automatically every 365 days. Old key signs new public key for continuity proof. New Shamir shares generated on rotation.

---

## Wallet Provenance Gate

Wallet addresses must originate from KYC-compliant centralised exchanges. Address format validated locally. Provenance verified via on-chain analytics provider configured by the institution.

Colour Foundation does not perform identity verification, store wallet addresses, or store provenance check results.

---

# PART 2 — COLOUR SHIELD

## Overview

Colour Shield intercepts package manager commands before execution, runs every package through a multi-layer security pipeline, and only permits installation if all checks pass.

```
Developer runs:  npm install express
                       ↓
          Colour Shield intercepts
                       ↓
         Layer 1: Known DB      — 15+ confirmed malicious packages
         Layer 2: Typosquat     — Exact + Levenshtein fuzzy match
         Layer 3: PQ Signature  — ML-DSA-87 + SPHINCS+-256
         Layer 4: Metadata      — Integrity, maintainers, age
         Layer 5: Audit Log     — Tamper-evident chain hash
                       ↓
            PASS → npm install runs
            FAIL → blocked, logged
```

---

## Components

### src/verifier.js
Core threat detection engine. Runs every package through all security layers.

Exports: verifyPackage, checkTyposquat, levenshtein, computeProvenanceHash, BUNDLED_THREATS, TYPOSQUAT_MAP, SEVERITY

### src/interceptor.js
Package manager interception layer. Supports npm, yarn, pnpm, bun, pip, pip3, poetry, cargo.

### src/audit.js
Immutable tamper-evident audit log. Chain-hashed NDJSON at ~/.colour-shield/audit.log.

### src/cli.js
Commands: npm, yarn, pnpm, bun, pip, pip3, cargo, scan, audit, report, test

### src/index.js
Public programmatic API.

### registry/registry.json
Signed registry of the top 90 npm packages with provenance hashes.

### scripts/stamp-top-100.js
Automated stamping script. Fetches integrity hashes from npm and writes signed entries.

---

## Post-Quantum Layer

When the Colour core binary is present at ~/.colour-shield/core/colour-core:

- ML-DSA-87 (FIPS 204) — primary signing
- SPHINCS+-SHA2-256s (FIPS 205) — secondary hash-based signing
- BLAKE3 — payload hashing
- SHA-256 — provenance chain

Both algorithms must pass.

```
colour-core keygen    — generate keypair
colour-core sign      — sign a package
colour-core verify    — verify a package
colour-core health    — check status
```

---

## Audit Chain

```
Entry 1: chainHash = SHA256(data + "GENESIS")
Entry 2: chainHash = SHA256(data + entry1.chainHash)
Entry 3: chainHash = SHA256(data + entry2.chainHash)
```

Verify integrity: colour-shield audit --verify-chain

---

## MCP Integration

```
POST /shield/install — verify and install
GET  /shield/scan   — verify without installing
GET  /shield/status — check post-quantum core
```

---

## Directory Structure

```
colour-shield/
├── src/
│   ├── verifier.js
│   ├── interceptor.js
│   ├── audit.js
│   ├── cli.js
│   └── index.js
├── tests/
│   ├── verifier.test.js
│   ├── audit.test.js
│   ├── interceptor.test.js
│   └── run.js
├── registry/
│   └── registry.json
├── scripts/
│   └── stamp-top-100.js
├── package.json
├── README.md
└── ARCHITECTURE.md
```

---

# PART 3 — SHARED INFRASTRUCTURE

## Colour Core (Rust)

The Rust core is the cryptographic foundation for both Vault and Shield.

Location: core/src/
Language: Rust 1.75+

Key modules:
- keygen/ — post-quantum key generation
- signing/ — ML-DSA-87 and SPHINCS+ signing
- enclave/ — hardware secure enclave interface
- encryption/ — AES-256-GCM + ChaCha20-Poly1305
- recovery/ — Shamir secret sharing
- memory/ — secure memory management
- sidechannel/ — constant-time operations
- replay/ — anti-replay nonce registry
- verify/ — Colour Shield package verification CLI

## MCP Server

Vault endpoints:
- GET  /health
- POST /provenance/check
- GET  /mcp/capabilities
- GET  /compliance/bundle

Shield endpoints:
- POST /shield/install
- GET  /shield/scan
- GET  /shield/status

---

## What This Codebase Is Not

- A replacement for an independent security audit
- A guarantee of zero vulnerabilities
- A formally certified product

The foundation is committed to independent third-party audit. Results will be published in AUDIT_LOG.md regardless of findings.

---

## Security Contact

buildwithcolours@gmail.com

Do not open public issues for security vulnerabilities.
