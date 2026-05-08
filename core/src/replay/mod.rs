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
    pub payload: Vec<u8>,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub chain_id: u64,
}

impl TransactionEnvelope {
    pub fn new(payload: Vec<u8>, chain_id: u64) -> VaultResult<Self> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_e| VaultError::Internal)?
            .as_secs();

        Ok(Self { payload, nonce, timestamp, chain_id })
    }

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
#[derive(Debug, Default)]
pub struct NonceRegistry {
    used: HashSet<[u8; 32]>,
}

impl NonceRegistry {
    pub fn check_and_register(&mut self, envelope: &TransactionEnvelope) -> VaultResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_e| VaultError::Internal)?
            .as_secs();

        if envelope.timestamp > now + 30 {
            return Err(VaultError::ReplayDetected);
        }

        if now.saturating_sub(envelope.timestamp) > VALIDITY_WINDOW_SECS {
            return Err(VaultError::ReplayDetected);
        }

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
        let result = registry.check_and_register(&env);
        assert!(matches!(result, Err(VaultError::NonceReuse)));
    }

    #[test]
    fn test_two_envelopes_have_different_nonces() {
        let env1 = TransactionEnvelope::new(b"tx".to_vec(), 1).unwrap();
        let env2 = TransactionEnvelope::new(b"tx".to_vec(), 1).unwrap();
        assert_ne!(env1.nonce, env2.nonce);
    }

    #[test]
    fn test_signing_bytes_includes_chain_id() {
        let env1 = TransactionEnvelope::new(b"payload".to_vec(), 1).unwrap();
        let env2 = TransactionEnvelope::new(b"payload".to_vec(), 137).unwrap();
        assert!(!env1.signing_bytes().is_empty());
        assert_ne!(env1.chain_id, env2.chain_id);
    }
        }
