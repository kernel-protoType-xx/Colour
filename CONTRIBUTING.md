# Contributing to Colour Vault

Thank you for your interest in contributing.

## Before You Start

Read `ARCHITECTURE.md` fully. Understand the threat model before touching any cryptographic code.

## Golden Rules

1. **Never implement cryptography from scratch.** Use the established libraries listed in `Cargo.toml`. If you think a new primitive is needed, open an issue first.
2. **Never log sensitive data.** Keys, secrets, addresses, and passphrases must never appear in logs. Use `[REDACTED]` in debug implementations.
3. **All sensitive types must implement `ZeroizeOnDrop`.** No exceptions.
4. **All comparisons on secret data must be constant-time.** Use the `subtle` crate.
5. **Every function must have a docstring.** Auditors read docs. Make their job easier.

## Contributor Licence Agreement

By submitting a pull request you confirm that:
- You have the right to submit the code
- You licence your contribution under Apache 2.0
- The Colour Foundation may include your contribution in the project

## Development Setup

```bash
git clone https://github.com/colour-foundation/colour-vault
cd colour-vault/core
cargo build
cargo test
cargo clippy -- -D warnings
cargo audit
```

## Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b fix/description` or `feat/description`
3. Write tests for any new code — coverage must not decrease
4. Run `cargo test`, `cargo clippy`, `cargo audit` — all must pass
5. Update relevant documentation
6. Open a pull request with a clear description

## Code Review Standards

- Cryptographic changes require review from at least two maintainers
- All CI checks must pass before merge
- No `unsafe` code without documented justification and two-maintainer approval

## Reporting Security Issues

See `SECURITY.md`. Do not open public issues for vulnerabilities.

## Contact

buildwithcolours@gmail.com
