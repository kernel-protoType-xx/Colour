# Colour Vault — Architecture

This document describes the technical architecture of the Colour Vault protocol. It is written for engineers, security researchers, and auditors.

---

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

The last point is worth stating plainly: if a fundamental flaw is discovered in ML-KEM-1024, ML-DSA-87, or the underlying lattice mathematics, the vault's security would be weakened. This is mitigated by the use of independent algorithm families (see Layer 1 and Layers 15–16), but not eliminated.

---

## Security Layers

### Layer 1 — Post-Quantum Key Generation

Three independent NIST-standardised algorithms are used simultaneously.

**ML-KEM-1024 (FIPS 203)**
- Lattice-based key encapsulation mechanism
- Security level: NIST Level 5 (≥256-bit classical, ≥128-bit quantum)
- Used for: key encapsulation and transport

**ML-DSA-87 (FIPS 204)**
- Lattice-based digital signature algorithm (formerly CRYSTALS-Dilithium)
- Security level: NIST Level 5
- Used for: primary transaction signing

**SPHINCS+-SHA2-256f (FIPS 205)**
- Hash-based digital signature scheme
- Security level: NIST Level 5
- Security assumption: SHA-256 collision resistance only — independent of lattice assumptions
- Used for: secondary transaction signing (redundant, independent assumption)

Both ML-DSA and SPHINCS+ must verify for a transaction to be considered valid. An attacker must simultaneously break a lattice-based scheme and a hash-based scheme to forge a signature.

### Layer 2 — Hardware Secure Enclave

Key generation and signing occur inside the device's hardware security boundary.

| Platform | Technology |
|---|---|
| iOS | Secure Enclave Processor |
| Android | StrongBox Keymaster (where available), TEE fallback |
| Desktop | TPM 2.0 (where available) |

The application process never holds raw private key bytes. The enclave returns only signed outputs. This is the same fundamental design as a hardware wallet.

On platforms without a hardware enclave, keys are held in encrypted memory using the software layer (Layer 4) with a clear warning to the user.

### Layer 3 — Multi-Party Computation (MPC)

For institutional deployments, threshold signatures using MPC ensure that no single party or device holds a complete key.

- Threshold: configurable, minimum 2-of-3
- Protocol: based on the GG20 threshold ECDSA protocol, adapted for post-quantum signing
- Key never reconstructed in full: signing happens in distributed fashion

This layer is optional for individual users and mandatory for institutional deployments handling significant assets.

### Layer 4 — Symmetric Encryption at Rest

All vault data stored outside the enclave is double-encrypted.

**Layer 4a — AES-256-GCM**
- 256-bit key derived via Argon2id
- Authenticated encryption — tampering detected

**Layer 4b — ChaCha20-Poly1305**
- 256-bit key derived independently via Argon2id
- Software-based cipher — immune to cache-timing attacks present in some AES hardware implementations

Ciphertext is: `ChaCha20-Poly1305( AES-256-GCM( plaintext ) )`

Both authentication tags must verify during decryption. Failure of either tag results in a deliberate opaque error (`VaultError::Decryption`) to prevent decryption oracle attacks.

**Key Derivation**

Argon2id with parameters:
- Memory: 64 MiB
- Iterations: 3
- Parallelism: 4
- Output: 64 bytes (split into two independent 32-byte keys)

These parameters exceed OWASP minimums and are calibrated for usability on low-end hardware.

### Layer 5 — Shamir Secret Sharing (3-of-5)

The vault master secret is split into 5 shares at creation. Any 3 reconstruct it.

- Scheme: Shamir's Secret Sharing over GF(256)
- Total shares: 5
- Threshold: 3
- Information-theoretic security: fewer than 3 shares reveal zero information about the secret

Users distribute shares to trusted parties or locations. No single share holder can access the vault alone. Losing 2 shares does not affect recoverability. Only losing 3 or more shares makes recovery impossible.

### Layer 6 — Zero-Knowledge Proofs

zk-STARKs (Scalable Transparent Arguments of Knowledge) are used to prove vault ownership and transaction validity without revealing underlying key material.

- Scheme: STARKs (not SNARKs — no trusted setup required)
- Post-quantum safe: security rests on hash function collision resistance
- Used for: proving ownership to institutional verifiers without key disclosure

### Layer 7 — Side-Channel Attack Mitigation

**Constant-time operations**

All comparisons involving secret data use constant-time functions from the `subtle` crate. This prevents timing oracles where an attacker infers secret values by measuring how long operations take.

**Memory access patterns**

Cryptographic operations are structured to avoid secret-dependent memory access patterns that could leak information via cache-timing attacks.

### Layer 8 — Secure Memory Management

- All sensitive types implement `Zeroize` and `ZeroizeOnDrop` via the `zeroize` crate
- `zeroize` uses `write_volatile` and compiler fences to prevent optimisation-away of zeroing
- `SecureBuffer` type wraps all temporary sensitive byte allocations
- Debug implementations for sensitive types output `[REDACTED]` — secret bytes never appear in logs

### Layer 9 — Supply Chain Security

**Reproducible builds**

The release binary is built deterministically. Any party can clone the repository, follow the build instructions, and verify their binary matches the published release hash.

**Dependency pinning**

All dependencies are pinned to exact versions with cryptographic hashes in `Cargo.lock` and `package-lock.json`. Dependency updates require explicit review.

**Automated vulnerability scanning**

`cargo audit` and `npm audit` run on every commit via GitHub Actions. Known vulnerable dependencies block the build.

**Signed releases**

Every release tag is GPG-signed by the foundation's release key. The public key is published in `SECURITY.md`.

### Layer 10 — Anti-Replay Protection

Every transaction envelope contains:

- 32-byte random nonce (unique per transaction)
- Unix timestamp (validity window: 5 minutes)
- Chain ID binding (transaction only valid on one specific network)

A nonce registry tracks used nonces. Any attempt to submit a previously seen nonce is rejected before signing.

### Layer 11 — Protocol Hardening

- Minimum cipher suite is full post-quantum — no legacy fallback path
- Perfect Forward Secrecy: session keys derived fresh per session; compromise of long-term keys does not expose past sessions
- All MCP communications require TLS 1.3 minimum

### Layer 12 — Formal Verification

Critical paths in the Rust core are verified using the Kani model checker:

- Key generation: verified to produce keys of correct length and format
- Encryption/decryption roundtrip: verified correct
- Shamir split/reconstruct: verified correct for all threshold combinations
- Nonce registry: verified to reject duplicate nonces

Formal verification is not a complete proof of security — it proves the implementation matches its specification, not that the specification is complete.

### Layer 13 — Entropy Quality

All randomness flows through `EntropySource`, which:

- Draws from the OS CSPRNG (`getrandom`) as the primary source
- Optionally mixes in external QRNG data via BLAKE3 (additive — cannot weaken OS entropy)
- Validates the entropy pool before key generation (rejects degenerate outputs)

### Layer 14 — QKD-Compatible Design

The protocol is designed to be compatible with Quantum Key Distribution hardware. Institutions with QKD infrastructure can integrate it at the key transport layer without protocol changes.

### Layer 15 — NTRU Prime

A second independent lattice-based scheme (NTRU Prime, by Daniel Bernstein et al.) is available as an additional key encapsulation layer for high-security institutional deployments.

NTRU Prime uses a different lattice construction from ML-KEM. A mathematical breakthrough against one does not transfer to the other.

### Layer 16 — XMSS-SHA512

XMSS (eXtended Merkle Signature Scheme, RFC 8391) provides a third signing algorithm based entirely on SHA-512.

- No lattice mathematics — pure hash-based security
- Standardised by NIST and IETF
- Used by several national security agencies today
- SHA-512 under Grover's algorithm: effective ~256-bit security — computationally infeasible

---

## Multichain Key Derivation

One vault generates one master key. Chain-specific keys are derived using BIP-44 paths:

| Chain | Derivation Path | Signature Scheme |
|---|---|---|
| Bitcoin | m/44'/0'/0'/0/0 | secp256k1 (P2WPKH) |
| Ethereum | m/44'/60'/0'/0/0 | secp256k1 (EIP-155) |
| Solana | m/44'/501'/0'/0' | Ed25519 |

Chain-native signature schemes are used for on-chain transactions as required by each network's consensus rules. Post-quantum signatures apply at the vault protocol level.

---

## Key Rotation

Keys rotate automatically every 365 days:

1. Rotation due date checked on vault open
2. New key pair generated with fresh entropy
3. Old key signs new public key (continuity proof)
4. New key stored in enclave, old key zeroized
5. New Shamir shares generated
6. User notified to redistribute shares

---

## Wallet Provenance Gate

Wallet addresses must originate from KYC-compliant centralised exchanges. Address format is validated locally. Provenance is verified via an on-chain analytics provider configured by the institution (individual users use the default integration).

Colour Foundation:
- Does not perform identity verification
- Does not store wallet addresses
- Does not store provenance check results

---

## What This Codebase Is Not

This repository is a well-structured implementation of the Colour Vault protocol built with established, audited libraries. It is not:

- A replacement for an independent security audit
- A guarantee of zero vulnerabilities
- A formally certified product

The foundation is committed to independent third-party audit. Results will be published in `AUDIT_LOG.md` regardless of findings.

---

## Contact

Colour Foundation — buildwithcolours@gmail.com
