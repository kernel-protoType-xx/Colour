//! Wallet provenance verification.
//!
//! Colour Vault requires that wallet addresses originate from KYC-compliant
//! centralised exchanges. This module provides the provenance check interface.
//!
//! ## What This Module Does
//!
//! - Validates that a wallet address format is correct for its chain
//! - Provides an interface to on-chain analytics providers for provenance
//!
//! ## What This Module Does NOT Do
//!
//! - Store any user identity information
//! - Perform KYC — that is the exchange's responsibility
//! - Guarantee absolute provenance — on-chain analytics is probabilistic
//!
//! ## Production Integration
//!
//! In production deployments, integrate an on-chain analytics provider
//! (Chainalysis, Elliptic, TRM Labs) via the `ProvenanceChecker` trait.
//! The trait is defined here; implementations are provider-specific and
//! kept in separate crates to avoid vendor lock-in.
//!
//! ## Privacy Note
//!
//! Only the wallet address is submitted for provenance checking.
//! No IP address, device identifier, or personal information is included.

use serde::{Deserialize, Serialize};

use crate::chains::Chain;
use crate::error::{VaultError, VaultResult};

/// The result of a provenance check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProvenanceStatus {
    /// Address verified as originating from a KYC-compliant exchange
    Verified,
    /// Address origin could not be determined
    Unverified,
    /// Address is associated with known illicit activity
    Rejected,
}

/// A provenance check request.
#[derive(Debug, Clone)]
pub struct ProvenanceRequest {
    /// The wallet address to check
    pub address: String,
    /// The chain this address belongs to
    pub chain: Chain,
}

/// Trait for on-chain analytics providers.
///
/// Implement this trait to integrate a specific provenance provider.
/// The vault calls `check` before allowing a new wallet to be added.
pub trait ProvenanceChecker: Send + Sync {
    /// Check the provenance of a wallet address.
    fn check(&self, request: &ProvenanceRequest) -> VaultResult<ProvenanceStatus>;
}

/// A provenance checker that accepts all addresses.
///
/// # Warning
///
/// This implementation is for development and testing ONLY.
/// It must not be used in production deployments.
/// In production, use a real on-chain analytics provider.
#[cfg(feature = "dev-mode")]
pub struct PermissiveChecker;

#[cfg(feature = "dev-mode")]
impl ProvenanceChecker for PermissiveChecker {
    fn check(&self, _request: &ProvenanceRequest) -> VaultResult<ProvenanceStatus> {
        // DEVELOPMENT ONLY — accepts all addresses
        Ok(ProvenanceStatus::Verified)
    }
}

/// Validate the format of a wallet address for a given chain.
///
/// This is a syntactic check only — it does not verify provenance.
pub fn validate_address_format(address: &str, chain: Chain) -> VaultResult<()> {
    match chain {
        Chain::Ethereum => validate_ethereum_address(address),
        Chain::Bitcoin => validate_bitcoin_address(address),
        Chain::Solana => validate_solana_address(address),
    }
}

fn validate_ethereum_address(address: &str) -> VaultResult<()> {
    if !address.starts_with("0x") {
        return Err(VaultError::InvalidParameter(
            "Ethereum address must start with 0x".to_string(),
        ));
    }
    let hex_part = &address[2..];
    if hex_part.len() != 40 {
        return Err(VaultError::InvalidParameter(
            "Ethereum address must be 40 hex characters after 0x".to_string(),
        ));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError::InvalidParameter(
            "Ethereum address contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_bitcoin_address(address: &str) -> VaultResult<()> {
    // Accept bech32 (bc1...) addresses — mainnet only
    if !address.starts_with("bc1") {
        return Err(VaultError::InvalidParameter(
            "only bech32 (bc1...) Bitcoin addresses are accepted".to_string(),
        ));
    }
    if address.len() < 26 || address.len() > 90 {
        return Err(VaultError::InvalidParameter(
            "Bitcoin address length is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_solana_address(address: &str) -> VaultResult<()> {
    // Solana addresses are base58-encoded Ed25519 public keys: 32-44 chars
    if address.len() < 32 || address.len() > 44 {
        return Err(VaultError::InvalidParameter(
            "Solana address length is invalid".to_string(),
        ));
    }
    const BASE58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if !address.chars().all(|c| BASE58_CHARS.contains(c)) {
        return Err(VaultError::InvalidParameter(
            "Solana address contains invalid base58 characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ethereum_address() {
        let addr = "0x62cbb29AF89E95Ce4229A53fe55C41891c5B3671";
        assert!(validate_address_format(addr, Chain::Ethereum).is_ok());
    }

    #[test]
    fn test_ethereum_missing_prefix_rejected() {
        assert!(validate_address_format(
            "62cbb29AF89E95Ce4229A53fe55C41891c5B3671",
            Chain::Ethereum
        )
        .is_err());
    }

    #[test]
    fn test_ethereum_wrong_length_rejected() {
        assert!(validate_address_format("0x1234", Chain::Ethereum).is_err());
    }

    #[test]
    fn test_valid_bitcoin_address() {
        let addr = "bc1qkaz97q5d93dlp9pd82x6qaecmsvm6a4tma8fwm";
        assert!(validate_address_format(addr, Chain::Bitcoin).is_ok());
    }

    #[test]
    fn test_bitcoin_legacy_address_rejected() {
        // Legacy P2PKH addresses (1...) not accepted — bech32 only
        assert!(validate_address_format("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Chain::Bitcoin).is_err());
    }

    #[test]
    fn test_valid_solana_address() {
        let addr = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        assert!(validate_address_format(addr, Chain::Solana).is_ok());
    }

    #[test]
    fn test_solana_invalid_chars_rejected() {
        assert!(validate_address_format("0invalid!address", Chain::Solana).is_err());
    }
}
