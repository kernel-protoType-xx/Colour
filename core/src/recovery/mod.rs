use sharks::{Share, Sharks};
use zeroize::ZeroizeOnDrop;
use crate::error::{VaultError, VaultResult};

const TOTAL_SHARES: u8 = 5;
const THRESHOLD: u8 = 3;

#[derive(Clone, ZeroizeOnDrop)]
pub struct RecoveryShare {
    #[zeroize(skip)]
    index: u8,
    bytes: Vec<u8>,
}

impl RecoveryShare {
    pub fn index(&self) -> u8 { self.index }
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    pub fn from_bytes(index: u8, bytes: Vec<u8>) -> Self { Self { index, bytes } }
}

impl std::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("index", &self.index)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub struct ShamirRecovery;

impl ShamirRecovery {
    pub fn split(secret: &[u8]) -> VaultResult<Vec<RecoveryShare>> {
        if secret.is_empty() {
            return Err(VaultError::InvalidParameter("secret must not be empty".to_string()));
        }
        let sharks = Sharks(THRESHOLD);
        let dealer = sharks.dealer(secret);
        let shares: Vec<RecoveryShare> = dealer
            .take(TOTAL_SHARES as usize)
            .enumerate()
            .map(|(i, share)| RecoveryShare {
                index: (i + 1) as u8,
                bytes: Vec::from(&share),
            })
            .collect();
        Ok(shares)
    }

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
        sharks.recover(&shark_shares)
            .map_err(|e| VaultError::SecretSharing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_produces_five_shares() {
        let shares = ShamirRecovery::split(b"test secret data must be long enough ok").unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_reconstruct_with_three_shares() {
        let secret = b"test secret data must be long enough ok";
        let shares = ShamirRecovery::split(secret).unwrap();
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = ShamirRecovery::reconstruct(&subset).unwrap();
        assert_eq!(secret.to_vec(), recovered);
    }

    #[test]
    fn test_two_shares_insufficient() {
        let shares = ShamirRecovery::split(b"test secret data must be long enough ok").unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        assert!(ShamirRecovery::reconstruct(&subset).is_err());
    }
}
