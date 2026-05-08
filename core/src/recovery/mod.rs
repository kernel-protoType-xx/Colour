//! Shamir Secret Sharing for vault recovery.
//!
//! This module implements 3-of-5 Shamir Secret Sharing for vault recovery.
//! A user's master secret is split into 5 shares at vault creation time.
//! Any 3 shares are sufficient to reconstruct the secret.
//!
//! ## Security Properties
//!
//! - Fewer than 3 shares reveal nothing about the secret (information-theoretic)
//! - 3 or more shares reconstruct the secret exactly
//! - Shares are independent — compromising 2 shares gives zero information
//!
//! ## User Flow
//!
//! 1. Vault is created → 5 shares generated
//! 2. User distributes shares to 5 trusted parties or locations
//! 3. Device lost → user collects any 3 shares → vault recovered
//! 4. No seed phrase. No single point of failure.

use sharks::{Share, Sharks};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};

/// Total shares generated
const TOTAL_SHARES: u8 = 5;
/// Minimum shares required for reconstruction
const THRESHOLD: u8 = 3;

/// A single Shamir share.
///
/// Each share is an opaque byte string that must be stored securely.
/// A share by itself reveals nothing about the secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecoveryShare {
    #[zeroize(skip)]
    index: u8,
    bytes: Vec<u8>,
}

impl RecoveryShare {
    /// The share index (1-based, 1 through 5)
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The raw share bytes for storage
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct a share from stored bytes
    pub fn from_bytes(index: u8, bytes: Vec<u8>) -> Self {
        Self { index, bytes }
    }
}

impl std::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("index", &self.index)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Shamir recovery handler
pub struct ShamirRecovery;

impl ShamirRecovery {
    /// Split a secret into 5 shares, requiring 3 to reconstruct.
    ///
    /// The secret is consumed and the caller receives 5 independent shares.
    /// The shares should be distributed to different trusted parties or locations.
    ///
    /// # Parameters
    ///
    /// - `secret`: The master secret to protect. Must not be empty.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::SecretSharing` if splitting fails.
    pub fn split(secret: &[u8]) -> VaultResult<Vec<RecoveryShare>> {
        if secret.is_empty() {
            return Err(VaultError::InvalidParameter(
                "secret must not be empty".to_string(),
            ));
        }

        let sharks = Sharks(THRESHOLD);
        let dealer = sharks.dealer(secret);

        let shares: Vec<RecoveryShare> = dealer
            .take(TOTAL_SHARES as usize)
            .enumerate()
            .map(|(i, share)| {
                let bytes: Vec<u8> = Vec::from(&share);
                RecoveryShare {
                    index: (i + 1) as u8,
                    bytes,
                }
            })
            .collect();

        if shares.len() != TOTAL_SHARES as usize {
            return Err(VaultError::SecretSharing(
                "failed to generate all shares".to_string(),
            ));
        }

        Ok(shares)
    }

    /// Reconstruct a secret from at least 3 shares.
    ///
    /// # Parameters
    ///
    /// - `shares`: At least 3 `RecoveryShare` values. Order does not matter.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::InsufficientShares` if fewer than 3 shares are provided.
    /// Returns `VaultError::SecretSharing` if reconstruction fails.
    pub fn reconstruct(shares: &[RecoveryShare]) -> VaultResult<Vec<u8>> {
        if shares.len() < THRESHOLD as usize {
            return Err(VaultError::InsufficientShares {
                needed: THRESHOLD,
                provided: shares.len(),
            });
        }

        let sharks = Sharks(THRESHOLD);

        let shark_shares: Vec<Share> = shares
            .iter()
            .map(|s| Share::try_from(s.bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VaultError::SecretSharing(e.to_string()))?;

        let secret = sharks
            .recover(&shark_shares)
            .map_err(|e| VaultError::SecretSharing(e.to_string()))?;

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"this is a 32 byte master secret!";

    #[test]
    fn test_split_produces_five_shares() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_shares_have_correct_indices() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.index(), (i + 1) as u8);
        }
    }

    #[test]
    fn test_reconstruct_with_all_five_shares() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        let recovered = ShamirRecovery::reconstruct(&shares).unwrap();
        assert_eq!(TEST_SECRET, recovered.as_slice());
    }

    #[test]
    fn test_reconstruct_with_exactly_three_shares() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        // Use shares 1, 3, 5
        let subset = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ];
        let recovered = ShamirRecovery::reconstruct(&subset).unwrap();
        assert_eq!(TEST_SECRET, recovered.as_slice());
    }

    #[test]
    fn test_reconstruct_with_different_three_shares() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        // Use shares 2, 3, 4
        let subset = vec![
            shares[1].clone(),
            shares[2].clone(),
            shares[3].clone(),
        ];
        let recovered = ShamirRecovery::reconstruct(&subset).unwrap();
        assert_eq!(TEST_SECRET, recovered.as_slice());
    }

    #[test]
    fn test_two_shares_insufficient() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let result = ShamirRecovery::reconstruct(&subset);
        assert!(
            matches!(result, Err(VaultError::InsufficientShares { needed: 3, provided: 2 })),
            "Two shares must not be sufficient for reconstruction"
        );
    }

    #[test]
    fn test_empty_secret_rejected() {
        let result = ShamirRecovery::split(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_shares_appear_random() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        // No two shares should be identical
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(
                    shares[i].bytes,
                    shares[j].bytes,
                    "All shares must be unique"
                );
            }
        }
    }

    #[test]
    fn test_debug_redacts_bytes() {
        let shares = ShamirRecovery::split(TEST_SECRET).unwrap();
        let debug = format!("{:?}", shares[0]);
        assert!(debug.contains("[REDACTED]"));
    }
}
