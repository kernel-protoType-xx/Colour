# Colour

**Open source. Post-quantum resistant. Client-side sovereign.**

Colour is a cryptographic protocol suite built by the Colour Foundation. It implements NIST-standardised post-quantum cryptography so that the assets you store and the software you install today remain secure against both classical and quantum adversaries.

No server holds your keys. No company holds your assets. No malicious package reaches your machine. The code is public. Trust is mathematical.

---

## What Colour Is

Colour is two things built on one cryptographic foundation:

### Colour Vault
A software vault — the cryptographic equivalent of a hardware wallet, running entirely on your own machine or your institution's own infrastructure.

- **Self-custody** — private keys generated and stored in your device's hardware secure enclave. They never leave it.
- **Post-quantum resistant** — built on ML-KEM-1024, ML-DSA-87, SPHINCS+-256, NTRU Prime, and XMSS. Multiple independent algorithm families so no single mathematical breakthrough compromises the vault.
- **Zero data custody** — Colour Foundation stores nothing. No keys, no addresses, no transaction history, no identity.
- **Multichain** — one vault, one master key, derived across Bitcoin, Ethereum, and Solana using BIP-44 with post-quantum wrapping.
- **Open source** — every line is public. Build it yourself from source and verify the binary matches.

### Colour Shield
A post-quantum package security layer — sits between developers and their package managers, blocking malicious packages, typosquats, and supply chain attacks before they reach the machine.

- **Universal** — works with npm, yarn, pnpm, bun, pip, pip3, cargo
- **Post-quantum verified** — ML-DSA-87 + SPHINCS+-256 signature verification
- **Immutable audit trail** — tamper-evident chain-hashed log of every package scan
- **90 packages pre-stamped** — top npm packages ship with provenance hashes
- **MCP integrated** — one command installs any package through your MCP server

---

## Who This Is For

| User | How they use Colour |
|---|---|
| Individual | Download the release binary, run locally, connect a KYC-verified exchange wallet |
| Developer | Install Colour Shield, secure every package install automatically |
| Institution | Deploy the MCP server on their own infrastructure with one command |
| Government | Run the sovereign deployment package, air-gapped if required |
| Enterprise | Colour Shield Enterprise for compliance reports and org-wide policy enforcement |

---

## Quick Start

### Colour Vault — Download a Release

Go to [Releases](https://github.com/thecolourfoundation/Colour/releases) and download for your platform:

- `colour-vault-windows.exe` — double click to run
- `colour-vault-mac.dmg` — double click to install
- `colour-vault-linux.AppImage` — double click to run

### Colour Vault — Build From Source

Prerequisites: Rust 1.75+, Node.js 20+

```bash
git clone https://github.com/thecolourfoundation/Colour
cd Colour

# Build the cryptographic core
cd core && cargo build --release

# Install the MCP server and interface
cd ../mcp && npm install
cd ../interface && npm install

# Run locally
npm start
```

### Colour Shield — Install

```bash
npm install -g colour-shield
```

### Colour Shield — Usage

```bash
# Secure wrappers — same commands you already use
colour-shield npm install express
colour-shield pip install requests
colour-shield cargo add serde

# Scan without installing
colour-shield scan axios
colour-shield scan axois          # blocked — typosquat detected
colour-shield scan event-stream@3.3.6  # blocked — known malicious

# Audit log
colour-shield audit
colour-shield audit --full
colour-shield audit --verify-chain

# Compliance report
colour-shield report --output report.json

# Self-test
colour-shield test
```

### Institution Deployment

```bash
npx colour-vault init
npx colour-vault deploy
```

The MCP server runs on your infrastructure. Nothing leaves your environment.

### Sovereign Deployment (Governments)

```bash
git clone https://github.com/thecolourfoundation/Colour
cd Colour
npm run deploy:sovereign
```

Generates compliance bundle, architecture attestation, and audit trail automatically.

---

## Security Architecture

### Colour Vault — 16 Security Layers

| Layer | Technology | Threat Defeated |
|---|---|---|
| 1 | ML-KEM-1024 + ML-DSA-87 + SPHINCS+-256 | Quantum attacks on key exchange and signing |
| 2 | Hardware Secure Enclave (iOS/Android/TPM) | Physical and software key extraction |
| 3 | Multi-Party Computation + Threshold Signatures | Single point of compromise |
| 4 | AES-256-GCM + ChaCha20-Poly1305 | Classical encryption attacks |
| 5 | Shamir Secret Sharing (3-of-5) | Seed phrase loss and theft |
| 6 | zk-STARKs | Identity and data exposure during verification |
| 7 | Constant-time operations | Timing and side-channel attacks |
| 8 | Secure memory allocation + zeroing | Memory dump and cold boot attacks |
| 9 | Reproducible deterministic builds | Supply chain and binary tampering |
| 10 | Nonce + timestamp + chain ID binding | Transaction replay attacks |
| 11 | Protocol hardening + Perfect Forward Secrecy | Protocol downgrade attacks |
| 12 | Kani formal verification on critical paths | Logic errors in cryptographic code |
| 13 | Quantum Random Number Generation | Weak randomness and key prediction |
| 14 | QKD-compatible protocol design | Physics-level interception |
| 15 | NTRU Prime (independent lattice) | Lattice mathematical breakthrough |
| 16 | XMSS-SHA512 (hash-based signing) | All remaining signature attacks |

### Colour Shield — 5 Security Layers

| Layer | Technology | Threat Defeated |
|---|---|---|
| 1 | Known malicious package database | Confirmed supply chain attacks |
| 2 | Typosquat detection (exact + fuzzy) | Fake package names |
| 3 | ML-DSA-87 + SPHINCS+-256 signatures | Tampered packages |
| 4 | Registry metadata analysis | Suspicious publish patterns |
| 5 | Tamper-evident audit chain | Log manipulation |

Full technical detail: [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Repository Structure

```
Colour/
├── core/                      # Rust — all cryptographic operations
│   ├── src/
│   │   ├── keygen/            # Post-quantum key generation
│   │   ├── enclave/           # Secure enclave interface
│   │   ├── encryption/        # Symmetric encryption layers
│   │   ├── recovery/          # Shamir secret sharing
│   │   ├── memory/            # Secure memory management
│   │   ├── sidechannel/       # Constant-time operations
│   │   ├── replay/            # Anti-replay protection
│   │   ├── protocol/          # Protocol hardening
│   │   ├── qrng/              # Quantum random number generation
│   │   ├── chains/            # Multichain abstraction
│   │   ├── signing/           # Offline transaction signing
│   │   ├── rotation/          # Automatic key rotation
│   │   └── verify/            # Colour Shield verification CLI
│   └── tests/
├── mcp/                       # TypeScript — institution MCP server
│   └── src/
│       └── server.ts          # Vault + Shield endpoints
├── colour-shield/             # JavaScript — package security layer
│   ├── src/
│   │   ├── verifier.js        # Threat detection engine
│   │   ├── interceptor.js     # Package manager interception
│   │   ├── audit.js           # Immutable audit chain
│   │   ├── cli.js             # Command line interface
│   │   └── index.js           # Public API
│   ├── tests/                 # 46 passing tests
│   ├── registry/              # 90 pre-stamped packages
│   └── scripts/               # Stamping automation
├── interface/                 # TypeScript — local user interface
├── scripts/                   # Deployment automation
└── docs/                      # Extended documentation
```

---

## Supported Chains

- Bitcoin (BTC)
- Ethereum (ETH) + ERC-20 tokens
- Solana (SOL)

Additional chains added via community governance.

---

## Payments and Licensing

Colour is free and open source under Apache 2.0 for personal and research use.

Commercial institutional use requires a licence.

**Email:** buildwithcolours@gmail.com

| Currency | Address |
|---|---|
| BTC | bc1qkaz97q5d93dlp9pd82x6qaecmsvm6a4tma8fwm |
| ETH | 0x62cbb29AF89E95Ce4229A53fe55C41891c5B3671 |
| USDC (ERC-20) | 0x62cbb29AF89E95Ce4229A53fe55C41891c5B3671 |
| USDT (ERC-20) | 0x62cbb29AF89E95Ce4229A53fe55C41891c5B3671 |

---

## Wallet Provenance Gate

Colour requires wallet addresses originating from KYC-compliant centralised exchanges. Wallet provenance is verified on-chain automatically at setup. Colour does not perform identity verification and stores no identity data.

This is a protocol-level decision. It is not configurable.

---

## Security Vulnerabilities

Do not open a public issue for security vulnerabilities. Read [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

---

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md). All contributions require signing the Contributor Licence Agreement.

---

## Audits

All security audit results are published in [AUDIT_LOG.md](./AUDIT_LOG.md) regardless of findings.

---

## Licence

Apache 2.0 — see [LICENSE](./LICENSE)

---

*Colour Foundation — buildwithcolours@gmail.com*
