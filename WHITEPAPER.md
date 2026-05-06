# Colour Vault: A Post-Quantum Resistant Open Source Cryptographic Vault Protocol

**Colour Foundation**  
buildwithcolours@gmail.com  
Version 0.1.0

---

## Abstract

We present Colour Vault, an open source cryptographic vault protocol implementing NIST-standardised post-quantum resistant algorithms for the secure generation, storage, and use of cryptocurrency private keys. Colour Vault operates entirely on client infrastructure — no key material ever traverses or rests on foundation-operated servers. The protocol combines ML-KEM-1024, ML-DSA-87, SPHINCS+-SHA2-256f, AES-256-GCM, ChaCha20-Poly1305, Argon2id, Shamir Secret Sharing, and zk-STARKs into a layered security model where each layer is independent. Compromise of any single layer does not compromise the vault. The protocol is designed for individual users, financial institutions, and governments. Integration is achieved via a Model Context Protocol (MCP) server that runs entirely within the integrating institution's own infrastructure.

---

## 1. Introduction

The security of cryptocurrency assets today rests primarily on elliptic curve cryptography — specifically secp256k1 and Ed25519. These schemes are computationally secure against classical computers. They are not secure against a sufficiently capable quantum computer running Shor's algorithm, which reduces the discrete logarithm problem to polynomial time.

The timeline for cryptographically relevant quantum computers is debated. NIST's post-quantum cryptography standardisation programme, which concluded in 2024 with the publication of FIPS 203, 204, and 205, reflects a consensus that migration to post-quantum algorithms should begin now. Financial institutions and governments are under increasing regulatory pressure to demonstrate quantum readiness.

Existing cryptocurrency vault solutions fall into three categories:

1. **Hardware wallets** (Ledger, Trezor): Secure enclaves in dedicated devices. Not post-quantum resistant. Require physical hardware.
2. **Software wallets** (MetaMask, Phantom): Convenient but typically store keys in software with limited isolation. Not post-quantum resistant.
3. **Institutional custody** (Fireblocks, Anchorage): MPC-based, high security, not open source, not post-quantum resistant, expensive.

Colour Vault addresses all three shortcomings: software-based (no hardware required), post-quantum resistant, open source, and free for individual users.

---

## 2. Design Principles

**2.1 Zero Data Custody**

Colour Foundation stores no user data. No keys. No addresses. No transaction history. No identity. This is not a policy — it is an architectural guarantee. The foundation operates no servers in the key management or signing path.

**2.2 Client-Side Sovereignty**

All cryptographic operations occur on hardware controlled by the user or institution. The vault runs locally. MCP servers run within institutional infrastructure. No operation requires contacting a Colour Foundation server.

**2.3 Open Source Trust**

The complete codebase is published under Apache 2.0. Trust is mathematical and empirical, not promised. Any party can read, audit, build, and verify the binary matches the source.

**2.4 Defence in Depth**

No single cryptographic algorithm is trusted absolutely. The protocol uses multiple independent algorithms from different mathematical families. A breakthrough against one family does not compromise the vault.

**2.5 Institutional Compatibility**

The protocol is designed to integrate with existing institutional infrastructure without requiring cryptographic expertise from the integrating engineers. One command deploys a fully configured MCP server.

---

## 3. Cryptographic Architecture

### 3.1 Key Generation

Keys are generated using three independent NIST-standardised post-quantum algorithms:

**ML-KEM-1024 (FIPS 203)** — Module Lattice-based Key Encapsulation Mechanism at security level 5. Provides key encapsulation with security reduction to the Module Learning With Errors (MLWE) problem.

**ML-DSA-87 (FIPS 204)** — Module Lattice-based Digital Signature Algorithm at security level 5. Provides signatures with security reduction to MLWE and Module Short Integer Solution (MSIS).

**SPHINCS+-SHA2-256f (FIPS 205)** — Stateless hash-based signature scheme at security level 5. Security rests entirely on SHA-256 collision resistance — an assumption independent of all lattice mathematics.

The use of both a lattice-based signer (ML-DSA) and a hash-based signer (SPHINCS+) means an adversary must simultaneously break two fundamentally different mathematical structures to forge a signature.

### 3.2 Entropy

All key generation flows through `EntropySource`, which draws from the operating system CSPRNG (`getrandom`). Optional external quantum random number generator data is mixed in via BLAKE3 XOF. The mixing is additive — weak QRNG data cannot reduce the entropy of the OS source.

### 3.3 Secure Enclave Integration

On supported platforms, private key bytes are generated inside and never exported from the hardware security boundary:

- iOS: Secure Enclave Processor (SEP)
- Android: StrongBox Keymaster (API 28+), TEE fallback
- Desktop: TPM 2.0 where available

The application process receives only signed outputs from the enclave. This is architecturally equivalent to a hardware wallet.

### 3.4 Symmetric Encryption

Vault data at rest is protected by two independent AEAD ciphers applied in sequence:

```
stored = ChaCha20-Poly1305_K2( AES-256-GCM_K1( plaintext ) )
```

Keys K1 and K2 are derived independently from the user passphrase via Argon2id (m=65536, t=3, p=4). Both authentication tags must verify during decryption — failure of either results in rejection.

### 3.5 Key Recovery

The vault master secret is split using Shamir's Secret Sharing (t=3, n=5). Security properties:

- Information-theoretic: fewer than 3 shares reveal zero bits about the secret
- Any 3 of 5 shares reconstruct exactly
- Individual share compromise is non-cumulative below threshold

### 3.6 Transaction Signing

Every transaction envelope contains:
- 32-byte cryptographically random nonce
- Unix timestamp (5-minute validity window)
- Chain ID binding

Both ML-DSA-87 and SPHINCS+ signatures are produced over the combined signing bytes. Both must verify for the transaction to be accepted. A nonce registry prevents replay.

---

## 4. Multichain Support

One master key derives chain-specific keys via BIP-44. Derivation paths follow convention:

| Chain | Path |
|---|---|
| Bitcoin | m/44'/0'/0'/0/0 |
| Ethereum | m/44'/60'/0'/0/0 |
| Solana | m/44'/501'/0'/0' |

Chain-native signature schemes are used for on-chain compatibility. Post-quantum signatures apply at the vault protocol level.

---

## 5. Institutional Integration

### 5.1 MCP Server

Institutions deploy a Model Context Protocol server within their own infrastructure:

```bash
npx colour-vault init
npx colour-vault deploy
```

The server exposes:
- `/health` — deployment health and capabilities
- `/provenance/check` — wallet address format and provenance validation
- `/mcp/capabilities` — protocol capabilities declaration
- `/compliance/bundle` — auto-generated compliance documentation

No vault operations route through Colour Foundation infrastructure.

### 5.2 Compliance Bundle

Each deployment generates a compliance bundle including:
- Data custody declaration (zero user data)
- Cryptographic standards mapping (NIST FIPS references)
- Regulatory notes (custodian status, KYC/AML responsibilities)

This document is suitable for submission to institutional legal and compliance teams.

---

## 6. Wallet Provenance

Colour Vault requires wallet addresses to originate from KYC-compliant centralised exchanges. Address format is validated locally. Provenance is verified via on-chain analytics (Chainalysis, Elliptic, or TRM Labs — institution's choice).

Colour Foundation:
- Does not perform identity verification
- Does not store wallet addresses or provenance results
- Does not have visibility into which users connect which wallets

---

## 7. Monetisation and Sustainability

The protocol is free for individual use under Apache 2.0. Commercial institutional use requires a licence. Revenue streams:

- Annual institutional licence fees
- Certification programme (Colour Certified deployments)
- Enterprise support contracts
- Sovereign government deployment contracts
- Foundation membership (governance participation)

The foundation does not issue tokens. Revenue funds protocol maintenance, security audits, and foundation operations.

---

## 8. Limitations and Honest Assessment

**Not yet independently audited.** This is the first public release. An independent audit by a recognised security firm is planned and results will be published regardless of findings.

**Post-quantum resistant, not post-quantum proof.** The protocol is resistant to known quantum attacks against the specified parameter sets. Unknown future attacks are not covered by any system.

**Secure enclave availability varies.** On platforms without hardware enclaves, the software encryption layer provides protection but without the physical isolation of dedicated hardware.

**On-chain transactions use classical signatures.** Bitcoin, Ethereum, and Solana require their native signature schemes. Post-quantum protection applies at the vault protocol layer.

---

## 9. Conclusion

Colour Vault provides the most comprehensive open source post-quantum resistant vault protocol available today. By combining multiple independent algorithm families, hardware enclave integration, zero data custody, and simple institutional integration, it addresses the full threat landscape facing cryptocurrency asset security in the quantum era.

The code is public. The architecture is documented. The audit will be published. Trust is earned, not promised.

---

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard
3. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard
4. RFC 9106 — Argon2 Memory-Hard Function for Password Hashing
5. RFC 8391 — XMSS: Extended Hash-Based Signatures
6. Shamir, A. (1979). How to Share a Secret. Communications of the ACM.
7. BIP-44 — Multi-Account Hierarchy for Deterministic Wallets

---

*Colour Foundation — buildwithcolours@gmail.com*
