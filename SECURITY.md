# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: buildwithcolours@gmail.com  
Subject line: `[SECURITY] Brief description`

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment

You will receive acknowledgement within 48 hours and a detailed response within 7 days.

## Disclosure Policy

- We will confirm receipt within 48 hours
- We will provide a fix timeline within 7 days
- We will notify you when the fix is released
- We will credit you in the release notes unless you prefer anonymity
- We ask for 90 days before public disclosure to allow patching

## Bug Bounty

| Severity | Payout |
|---|---|
| Critical — remote key extraction | $50,000 USDC |
| High — authentication bypass | $10,000 USDC |
| Medium — information disclosure | $2,500 USDC |
| Low — minor issues | $500 USDC |

Payments to: `0x62cbb29AF89E95Ce4229A53fe55C41891c5B3671` (USDC ERC-20)

## Scope

In scope:
- `core/` — all Rust cryptographic code
- `mcp/` — MCP server
- `interface/` — local user interface
- Protocol design and specification

Out of scope:
- Third-party dependencies (report to them directly)
- Social engineering attacks
- Physical attacks on user devices

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Known Limitations

See `ARCHITECTURE.md` — Threat Model section for documented limitations.
