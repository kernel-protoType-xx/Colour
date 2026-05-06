//! Error types for the Colour Vault core library.

use thiserror::Error;

/// The canonical error type for all vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Key generation failed
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption operation failed
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption operation failed — deliberately vague to avoid oracle attacks
    #[error("decryption failed")]
    Decryption,

    /// Shamir share generation or reconstruction failed
    #[error("secret sharing failed: {0}")]
    SecretSharing(String),

    /// Insufficient shares provided for reconstruction
    #[error("insufficient shares: need {needed}, got {provided}")]
    InsufficientShares { needed: u8, provided: usize },

    /// Wallet provenance verification failed
    #[error("wallet provenance could not be verified")]
    ProvenanceUnverified,

    /// Wallet originated from an unrecognised or non-KYC source
    #[error("wallet address rejected: unverified origin")]
    ProvenanceRejected,

    /// Nonce reuse detected — potential replay attack
    #[error("nonce reuse detected — transaction rejected")]
    NonceReuse,

    /// Transaction replay detected
    #[error("replay attack detected — transaction rejected")]
    ReplayDetected,

    /// Key rotation failed
    #[error("key rotation failed: {0}")]
    KeyRotation(String),

    /// Entropy source failure
    #[error("entropy source unavailable: {0}")]
    EntropyFailure(String),

    /// Unsupported chain
    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),

    /// Serialisation error
    #[error("serialisation error: {0}")]
    Serialisation(String),

    /// Invalid parameter
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Internal error — deliberately opaque externally
    #[error("internal error")]
    Internal,
}

/// Convenience result type
pub type VaultResult<T> = Result<T, VaultError>;
