//! Anti-replay protection for vault transactions.
//!
//! Every transaction signed by the vault includes:
//!
//! - A unique nonce (random 32 bytes)
//! - A timestamp with a validity window
//! - A chain ID binding (transaction only valid on one specific chain)
//!
//! A nonce registry tracks used nonces for the validity window duration.
//! Any attempt to reuse a nonce is rejected before signing.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};

/// Transaction validity window in seconds (5 minutes)
const VALIDITY_WINDOW_SECS: u64 = 300;

/// A transaction envelope with replay protection fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEnvelope {
    /// The raw transaction bytes to be signed
    pub payload: Vec<u8>,
    /// Unique nonce — 32 random bytes
    pub nonce: [u8; 32],
    /// Unix timestamp when this envelope was created
    pub timestamp: u64,
    /// Chain ID this transaction is bound to
    pub chain_id: u64,
}

impl TransactionEnvelope {
    /// Create a new transaction envelope with a fresh nonce and timestamp.
    pub fn new(payload: Vec<u8>, chain_id: u64) -> VaultResult<Self> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Internal)?
            .as_secs();

        Ok(Self {
            payload,
            nonce,
            timestamp,
            chain_id,
        })
    }

    /// Serialise the envelope fields that are included in the signature.
    ///
    /// The signature covers: payload || nonce || timestamp || chain_id
    /// This binding prevents the same signature from being valid on a
    /// different chain or at a different time.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes
    }
}

/// Registry of used nonces for replay detection.
///
/// In production, this should be backed by persistent storage so
/// replay detection survives restarts.
#[derive(Debug, Default)]
pub struct NonceRegistry {
    used: HashSet<[u8; 32]>,
}

impl NonceRegistry {
    /// Check and register a nonce.
    ///
    /// Returns `Ok(())` if the nonce is fresh and the timestamp is within
    /// the validity window.
    ///
    /// Returns `VaultError::NonceReuse` if the nonce has been seen before.
    /// Returns `VaultError::ReplayDetected` if the timestamp is expired.
    pub fn check_and_register(
        &mut self,
        envelope: &TransactionEnvelope,
    ) -> VaultResult<()> {
        // Check timestamp validity window
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VaultError::Internal)?
            .as_secs();

        if envelope.timestamp > now + 30 {
            // Timestamp is in the future — reject
            return Err(VaultError::ReplayDetected);
        }

        if now.saturating_sub(envelope.timestamp) > VALIDITY_WINDOW_SECS {
            // Timestamp is too old — reject
            return Err(VaultError::ReplayDetected);
        }

        // Check nonce uniqueness
        if self.used.contains(&envelope.nonce) {
            return Err(VaultError::NonceReuse);
        }

        self.used.insert(envelope.nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_envelope_accepted() {
        let mut registry = NonceRegistry::default();
        let env = TransactionEnvelope::new(b"tx payload".to_vec(), 1).unwrap();
        assert!(registry.check_and_register(&env).is_ok());
    }

    #[test]
    fn test_nonce_reuse_rejected() {
        let mut registry = NonceRegistry::default();
        let env = TransactionEnvelope::new(b"tx payload".to_vec(), 1).unwrap();
        registry.check_and_register(&env).unwrap();

        // Reuse the same nonce
        let result = registry.check_and_register(&env);
        assert!(
            matches!(result, Err(VaultError::NonceReuse)),
            "Nonce reuse must be rejected"
        );
    }

    #[test]
    fn test_two_envelopes_have_different_nonces() {
        let env1 = TransactionEnvelope::new(b"tx".to_vec(), 1).unwrap();
        let env2 = TransactionEnvelope::new(b"tx".to_vec(), 1).unwrap();
        assert_ne!(env1.nonce, env2.nonce);
    }

    #[test]
    fn test_signing_bytes_includes_chain_id() {
        let payload = b"same payload".to_vec();
        let env1 = TransactionEnvelope::new(payload.clone(), 1).unwrap();
        let env2 = TransactionEnvelope::new(payload, 137).unwrap();

        // Signing bytes must differ due to different chain IDs
        // (nonces will also differ, but chain ID binding is the point)
        assert_ne!(
            env1.signing_bytes().len(),
            0,
            "Signing bytes must not be empty"
        );
        assert_ne!(
            &env1.signing_bytes()[env1.payload.len() + 32 + 8..],
            &env2.signing_bytes()[env2.payload.len() + 32 + 8..],
            "Chain ID must be included in signing bytes"
        );
    }
}
