//! Offline transaction signing for Colour Vault.
//!
//! Transactions can be signed completely offline — the vault does not
//! require a network connection to sign. This is the software equivalent
//! of a hardware wallet's air-gapped signing capability.
//!
//! ## Offline Signing Flow
//!
//! 1. Transaction constructed (can be done online)
//! 2. Transaction transferred to offline vault (via QR code or file)
//! 3. Vault signs transaction offline using enclave keys
//! 4. Signed transaction transferred back online for broadcast
//!
//! ## What "Offline" Means Here
//!
//! The signing operation itself makes zero network calls.
//! Key material never touches the network.
//! The signed transaction bytes are the only output.
//!
//! ## Limitation
//!
//! This module does not enforce that the host machine is offline.
//! That is an operational concern for the user or institution.
//! The module guarantees only that IT makes no network calls.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{VaultError, VaultResult};
use crate::keygen::{DualSignature, VaultKeyPair};
use crate::replay::{NonceRegistry, TransactionEnvelope};

/// A signed transaction ready for broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The original transaction envelope
    pub envelope: TransactionEnvelope,
    /// Dual post-quantum signature over the envelope's signing bytes
    pub signature: DualSignature,
    /// Hex-encoded signing bytes for external verification
    pub signing_bytes_hex: String,
}

/// Sign a transaction envelope using the vault key pair.
///
/// This function makes no network calls. It can be called in a
/// completely offline environment.
///
/// # Parameters
///
/// - `envelope`: The transaction to sign (must pass replay check)
/// - `keypair`: The vault key pair holding the signing keys
/// - `registry`: Nonce registry for replay detection
///
/// # Errors
///
/// Returns `VaultError::ReplayDetected` or `VaultError::NonceReuse`
/// if the envelope fails replay checks.
pub fn sign_transaction(
    envelope: TransactionEnvelope,
    keypair: &VaultKeyPair,
    registry: &mut NonceRegistry,
) -> VaultResult<SignedTransaction> {
    // Replay check must pass before any signing occurs
    registry.check_and_register(&envelope)?;

    let signing_bytes = envelope.signing_bytes();
    let signature = keypair.sign(&signing_bytes)?;
    let signing_bytes_hex = hex::encode(&signing_bytes);

    Ok(SignedTransaction {
        envelope,
        signature,
        signing_bytes_hex,
    })
}

/// Verify a signed transaction without a key pair (public key only).
///
/// This can be called online by any verifier with access to the
/// vault's public components.
pub fn verify_signed_transaction(
    signed: &SignedTransaction,
    public: &crate::keygen::PublicComponents,
) -> bool {
    let signing_bytes = signed.envelope.signing_bytes();
    signed.signature.verify(&signing_bytes, public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrng::EntropySource;

    fn setup() -> (VaultKeyPair, NonceRegistry) {
        let entropy = EntropySource::os_only();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();
        let registry = NonceRegistry::default();
        (keypair, registry)
    }

    #[test]
    fn test_sign_and_verify() {
        let (keypair, mut registry) = setup();
        let envelope = TransactionEnvelope::new(b"send 1 btc".to_vec(), 1).unwrap();

        let signed = sign_transaction(envelope, &keypair, &mut registry).unwrap();
        let valid = verify_signed_transaction(&signed, &keypair.public);

        assert!(valid, "Freshly signed transaction must verify");
    }

    #[test]
    fn test_replay_rejected() {
        let (keypair, mut registry) = setup();
        let envelope = TransactionEnvelope::new(b"send 1 btc".to_vec(), 1).unwrap();

        // Clone envelope before first sign consumes it
        let envelope2 = envelope.clone();

        sign_transaction(envelope, &keypair, &mut registry).unwrap();

        // Attempt to sign the same envelope again — must fail
        let result = sign_transaction(envelope2, &keypair, &mut registry);
        assert!(
            matches!(result, Err(VaultError::NonceReuse)),
            "Replay of same nonce must be rejected"
        );
    }

    #[test]
    fn test_verification_fails_with_wrong_public_key() {
        let (kp1, mut registry) = setup();
        let entropy = EntropySource::os_only();
        let kp2 = VaultKeyPair::generate(&entropy).unwrap();

        let envelope = TransactionEnvelope::new(b"tx".to_vec(), 1).unwrap();
        let signed = sign_transaction(envelope, &kp1, &mut registry).unwrap();

        let valid = verify_signed_transaction(&signed, &kp2.public);
        assert!(!valid, "Verification with wrong public key must fail");
    }
}
