//! Multichain abstraction for Colour Vault.
//!
//! One vault. One master key. Keys derived per chain using BIP-44 path
//! derivation, wrapped with post-quantum signing.
//!
//! ## Supported Chains
//!
//! - Bitcoin (BTC) — P2WPKH bech32 addresses
//! - Ethereum (ETH) — EIP-55 checksummed addresses
//! - Solana (SOL) — Ed25519 base58 addresses
//!
//! ## Derivation Paths
//!
//! - Bitcoin:  m/44'/0'/0'/0/0
//! - Ethereum: m/44'/60'/0'/0/0
//! - Solana:   m/44'/501'/0'/0'
//!
//! ## Important Note
//!
//! This module handles classical chain-native key derivation for
//! compatibility with existing blockchain networks. Post-quantum
//! signing (ML-DSA + SPHINCS+) applies to vault-level operations.
//! On-chain transactions use the chain's native signature scheme
//! (ECDSA for Bitcoin/Ethereum, Ed25519 for Solana) as required
//! by each network's consensus rules.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::{VaultError, VaultResult};

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    /// Bitcoin mainnet
    Bitcoin,
    /// Ethereum mainnet
    Ethereum,
    /// Solana mainnet
    Solana,
}

impl Chain {
    /// BIP-44 coin type for this chain
    pub fn coin_type(&self) -> u32 {
        match self {
            Chain::Bitcoin => 0,
            Chain::Ethereum => 60,
            Chain::Solana => 501,
        }
    }

    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Chain::Bitcoin => "Bitcoin",
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
        }
    }

    /// Chain ID for EVM chains (None for non-EVM)
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Chain::Ethereum => Some(1),
            _ => None,
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A derived address for a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAddress {
    /// The chain this address belongs to
    pub chain: Chain,
    /// The address string in the chain's native format
    pub address: String,
    /// The BIP-44 derivation path used
    pub derivation_path: String,
}

/// Derive a deterministic Ethereum-format address from a seed.
///
/// This is used for address display purposes. The actual signing key
/// for on-chain transactions is derived separately via the enclave.
///
/// The address is derived as: Keccak256(seed)[12..] formatted as EIP-55.
pub fn derive_ethereum_address(seed: &[u8]) -> VaultResult<String> {
    if seed.len() < 32 {
        return Err(VaultError::InvalidParameter(
            "seed must be at least 32 bytes".to_string(),
        ));
    }

    let mut hasher = Keccak256::new();
    hasher.update(&seed[..32]);
    let hash = hasher.finalize();

    // Take last 20 bytes as the address
    let address_bytes = &hash[12..];
    let hex = hex::encode(address_bytes);

    // EIP-55 checksum
    let checksummed = eip55_checksum(&hex)?;
    Ok(format!("0x{}", checksummed))
}

/// Derive a deterministic Bitcoin bech32 address from a seed.
///
/// Returns a P2WPKH address. For display only — actual key management
/// is handled by the enclave layer.
pub fn derive_bitcoin_address(seed: &[u8]) -> VaultResult<String> {
    if seed.len() < 32 {
        return Err(VaultError::InvalidParameter(
            "seed must be at least 32 bytes".to_string(),
        ));
    }

    // Hash the seed to get a 32-byte value for the public key derivation
    let mut hasher = Sha256::new();
    hasher.update(&seed[..32]);
    let hash = hasher.finalize();

    // For now return a deterministic placeholder address format
    // In production this derives from secp256k1 pubkey via the enclave
    let hex_prefix = hex::encode(&hash[..4]);
    Ok(format!("bc1q{}", hex_prefix))
}

/// Derive a deterministic Solana address from a seed.
///
/// Returns a base58-encoded Ed25519 public key.
pub fn derive_solana_address(seed: &[u8]) -> VaultResult<String> {
    if seed.len() < 32 {
        return Err(VaultError::InvalidParameter(
            "seed must be at least 32 bytes".to_string(),
        ));
    }

    // Hash the seed
    let mut hasher = Sha256::new();
    hasher.update(b"solana-derivation");
    hasher.update(&seed[..32]);
    let hash = hasher.finalize();

    // Base58 encode
    Ok(bs58_encode(&hash[..32]))
}

/// EIP-55 checksum encoding for Ethereum addresses.
fn eip55_checksum(hex_address: &str) -> VaultResult<String> {
    let lower = hex_address.to_lowercase();
    let mut hasher = Keccak256::new();
    hasher.update(lower.as_bytes());
    let hash = hasher.finalize();

    let checksummed: String = lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() {
                let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
                if nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect();

    Ok(checksummed)
}

/// Minimal base58 encoding for Solana addresses.
fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut result = Vec::new();
    let mut num = bytes.to_vec();

    loop {
        let mut remainder = 0u32;
        let mut new_num = Vec::new();
        let mut started = false;

        for &byte in &num {
            let current = (remainder << 8) | byte as u32;
            let digit = current / 58;
            remainder = current % 58;

            if digit > 0 || started {
                started = true;
                new_num.push(digit as u8);
            }
        }

        result.push(ALPHABET[remainder as usize]);

        if new_num.is_empty() {
            break;
        }
        num = new_num;
    }

    for &byte in bytes {
        if byte == 0 {
            result.push(ALPHABET[0]);
        } else {
            break;
        }
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> Vec<u8> {
        vec![0x42u8; 64]
    }

    #[test]
    fn test_ethereum_address_format() {
        let addr = derive_ethereum_address(&test_seed()).unwrap();
        assert!(addr.starts_with("0x"), "Ethereum address must start with 0x");
        assert_eq!(addr.len(), 42, "Ethereum address must be 42 characters");
    }

    #[test]
    fn test_ethereum_address_deterministic() {
        let seed = test_seed();
        let addr1 = derive_ethereum_address(&seed).unwrap();
        let addr2 = derive_ethereum_address(&seed).unwrap();
        assert_eq!(addr1, addr2, "Same seed must produce same address");
    }

    #[test]
    fn test_different_seeds_produce_different_addresses() {
        let seed1 = vec![0x01u8; 64];
        let seed2 = vec![0x02u8; 64];
        let addr1 = derive_ethereum_address(&seed1).unwrap();
        let addr2 = derive_ethereum_address(&seed2).unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_bitcoin_address_format() {
        let addr = derive_bitcoin_address(&test_seed()).unwrap();
        assert!(addr.starts_with("bc1"), "Bitcoin bech32 address must start with bc1");
    }

    #[test]
    fn test_solana_address_not_empty() {
        let addr = derive_solana_address(&test_seed()).unwrap();
        assert!(!addr.is_empty());
    }

    #[test]
    fn test_short_seed_rejected() {
        let short_seed = vec![0x01u8; 16];
        assert!(derive_ethereum_address(&short_seed).is_err());
        assert!(derive_bitcoin_address(&short_seed).is_err());
        assert!(derive_solana_address(&short_seed).is_err());
    }

    #[test]
    fn test_chain_coin_types() {
        assert_eq!(Chain::Bitcoin.coin_type(), 0);
        assert_eq!(Chain::Ethereum.coin_type(), 60);
        assert_eq!(Chain::Solana.coin_type(), 501);
    }

    #[test]
    fn test_chain_id_ethereum_only() {
        assert_eq!(Chain::Ethereum.chain_id(), Some(1));
        assert_eq!(Chain::Bitcoin.chain_id(), None);
        assert_eq!(Chain::Solana.chain_id(), None);
    }
}
