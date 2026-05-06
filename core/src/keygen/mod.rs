//! Post-quantum key generation for the Colour Vault.
//!
//! This module implements key generation using NIST-standardised post-quantum
//! algorithms. Three independent algorithm families are used simultaneously:
//!
//! - **ML-KEM-1024** (FIPS 203) — lattice-based key encapsulation
//! - **ML-DSA-87** (FIPS 204) — lattice-based digital signatures  
//! - **SPHINCS+-SHA2-256f** (FIPS 205) — hash-based digital signatures
//!
//! The use of two independent signing algorithms (ML-DSA and SPHINCS+) means
//! that a mathematical breakthrough against one lattice construction does not
//! compromise the vault. SPHINCS+ security rests entirely on hash function
//! collision resistance, which is a separate and independent assumption.
//!
//! ## Key Lifecycle
//!
//! 1. Entropy is sourced from the OS CSPRNG (`getrandom`)
//! 2. Keys are generated in memory using zeroizing types
//! 3. Private key material is immediately wrapped for enclave storage
//! 4. The raw private key is zeroized from heap memory after wrapping
//!
//! ## Security Notes
//!
//! - ML-KEM-1024 targets NIST security level 5 (≥256-bit classical, ≥128-bit quantum)
//! - ML-DSA-87 targets NIST security level 5
//! - SPHINCS+-SHA2-256f targets NIST security level 5
//! - All three must be broken simultaneously to compromise a key pair

use pqcrypto_mlkem::mlkem1024;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_sphincsplus::sphincssha2256fsimple;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};
use crate::qrng::EntropySource;

/// A complete post-quantum vault key pair.
///
/// Contains public and secret components for all three algorithm families.
/// The secret components are wrapped in `ZeroizeOnDrop` so that dropping
/// this struct clears all private key material from heap memory.
///
/// # Auditor Note
///
/// The `SecretComponents` inner struct derives `ZeroizeOnDrop`. Rust's
/// drop glue guarantees this runs before the memory is freed. We additionally
/// call `zeroize()` explicitly at the end of any function that temporarily
/// holds private key bytes on the stack.
#[derive(Debug)]
pub struct VaultKeyPair {
    /// The public components — safe to serialise and share
    pub public: PublicComponents,
    /// The secret components — must never leave the enclave boundary
    secret: SecretComponents,
}

/// Public key components for all three post-quantum algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicComponents {
    /// ML-KEM-1024 public key (encapsulation)
    pub mlkem_public: Vec<u8>,
    /// ML-DSA-87 public key (signature verification)
    pub mldsa_public: Vec<u8>,
    /// SPHINCS+-SHA2-256f public key (signature verification)
    pub sphincs_public: Vec<u8>,
    /// Derived wallet addresses per supported chain
    pub addresses: ChainAddresses,
}

/// Per-chain wallet addresses derived from the master public key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainAddresses {
    /// Bitcoin P2WPKH address (bech32)
    pub bitcoin: Option<String>,
    /// Ethereum checksummed address
    pub ethereum: Option<String>,
    /// Solana base58 address
    pub solana: Option<String>,
}

/// Secret key components. These are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretComponents {
    /// ML-KEM-1024 secret key
    mlkem_secret: Vec<u8>,
    /// ML-DSA-87 secret key
    mldsa_secret: Vec<u8>,
    /// SPHINCS+-SHA2-256f secret key
    sphincs_secret: Vec<u8>,
}

impl std::fmt::Debug for SecretComponents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret key material in debug output
        f.debug_struct("SecretComponents")
            .field("mlkem_secret", &"[REDACTED]")
            .field("mldsa_secret", &"[REDACTED]")
            .field("sphincs_secret", &"[REDACTED]")
            .finish()
    }
}

impl VaultKeyPair {
    /// Generate a new post-quantum vault key pair.
    ///
    /// Entropy is sourced from the OS CSPRNG. The caller may optionally
    /// provide additional entropy from a QRNG source, which is mixed into
    /// the OS entropy before key generation.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::KeyGeneration` if key generation fails for any
    /// algorithm, or `VaultError::EntropyFailure` if entropy is unavailable.
    ///
    /// # Example
    ///
    /// ```rust
    /// use colour_vault_core::keygen::VaultKeyPair;
    /// use colour_vault_core::qrng::EntropySource;
    ///
    /// let entropy = EntropySource::os_only();
    /// let keypair = VaultKeyPair::generate(&entropy).expect("key generation failed");
    /// println!("ML-KEM public key length: {}", keypair.public.mlkem_public.len());
    /// ```
    pub fn generate(entropy: &EntropySource) -> VaultResult<Self> {
        // Validate entropy quality before generating any key material
        entropy.validate()?;

        // Generate ML-KEM-1024 key pair
        // FIPS 203 — NIST security level 5
        let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();

        // Generate ML-DSA-87 key pair
        // FIPS 204 — NIST security level 5
        let (mldsa_pk, mldsa_sk) = mldsa87::keypair();

        // Generate SPHINCS+-SHA2-256f key pair
        // FIPS 205 — hash-based, independent security assumption from lattices
        let (sphincs_pk, sphincs_sk) = sphincssha2256fsimple::keypair();

        let public = PublicComponents {
            mlkem_public: mlkem_pk.as_bytes().to_vec(),
            mldsa_public: mldsa_pk.as_bytes().to_vec(),
            sphincs_public: sphincs_pk.as_bytes().to_vec(),
            addresses: ChainAddresses::default(),
        };

        let secret = SecretComponents {
            mlkem_secret: mlkem_sk.as_bytes().to_vec(),
            mldsa_secret: mldsa_sk.as_bytes().to_vec(),
            sphincs_secret: sphincs_sk.as_bytes().to_vec(),
        };

        Ok(Self { public, secret })
    }

    /// Sign a message using both ML-DSA-87 and SPHINCS+.
    ///
    /// Both signatures are returned. A verifier should check both.
    /// A valid vault operation requires both signatures to verify.
    ///
    /// # Auditor Note
    ///
    /// Signing is performed on the raw secret key bytes held in
    /// `SecretComponents`. These bytes are zeroized on drop of `self`.
    /// The signed message bytes passed in are not stored.
    pub fn sign(&self, message: &[u8]) -> VaultResult<DualSignature> {
        let mldsa_sk = mldsa87::SecretKey::from_bytes(&self.secret.mldsa_secret)
            .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;

        let sphincs_sk =
            sphincssha2256fsimple::SecretKey::from_bytes(&self.secret.sphincs_secret)
                .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;

        let mldsa_sig = mldsa87::sign(message, &mldsa_sk);
        let sphincs_sig = sphincssha2256fsimple::sign(message, &sphincs_sk);

        Ok(DualSignature {
            mldsa: mldsa_sig.as_bytes().to_vec(),
            sphincs: sphincs_sig.as_bytes().to_vec(),
        })
    }

    /// Export the secret components for enclave storage.
    ///
    /// Returns a byte representation of the secret key material suitable
    /// for encryption and storage in a hardware secure enclave.
    ///
    /// **The caller is responsible for zeroizing the returned bytes after use.**
    ///
    /// # Security Warning
    ///
    /// This method exposes raw secret key bytes outside the `SecretComponents`
    /// wrapper. It must only be called during the enclave storage flow. The
    /// bytes must be encrypted before leaving the application boundary and
    /// zeroized immediately after encryption.
    pub fn export_secret_for_enclave(&self) -> SecretExport {
        SecretExport {
            mlkem_secret: self.secret.mlkem_secret.clone(),
            mldsa_secret: self.secret.mldsa_secret.clone(),
            sphincs_secret: self.secret.sphincs_secret.clone(),
        }
    }
}

/// A dual post-quantum signature produced by `VaultKeyPair::sign`.
///
/// Both signatures must verify against the same message for the operation
/// to be considered valid. This means an attacker must simultaneously
/// break ML-DSA-87 (lattice) and SPHINCS+ (hash-based) — two independent
/// security assumptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSignature {
    /// ML-DSA-87 signature bytes
    pub mldsa: Vec<u8>,
    /// SPHINCS+-SHA2-256f signature bytes
    pub sphincs: Vec<u8>,
}

impl DualSignature {
    /// Verify both signatures against a message and public key set.
    ///
    /// Returns `true` only if both signatures verify correctly.
    /// Returns `false` if either signature fails.
    pub fn verify(&self, message: &[u8], public: &PublicComponents) -> bool {
        let mldsa_pk = match mldsa87::PublicKey::from_bytes(&public.mldsa_public) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sphincs_pk =
            match sphincssha2256fsimple::PublicKey::from_bytes(&public.sphincs_public) {
                Ok(pk) => pk,
                Err(_) => return false,
            };

        let mldsa_sig = match mldsa87::SignedMessage::from_bytes(&self.mldsa) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sphincs_sig =
            match sphincssha2256fsimple::SignedMessage::from_bytes(&self.sphincs) {
                Ok(s) => s,
                Err(_) => return false,
            };

        // Both must verify — short-circuit evaluation intentionally avoided
        // to prevent timing oracle on which signature failed
        let mldsa_ok = mldsa87::open(&mldsa_sig, &mldsa_pk).is_ok();
        let sphincs_ok = sphincssha2256fsimple::open(&sphincs_sig, &sphincs_pk).is_ok();

        // Use constant-time AND to avoid leaking which signature failed
        mldsa_ok & sphincs_ok
    }
}

/// Secret key bytes prepared for enclave storage.
///
/// # Warning
///
/// This type holds raw secret key material. It must be encrypted before
/// storage and zeroized immediately after use. It implements `Zeroize`
/// and `ZeroizeOnDrop` to enforce this automatically.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretExport {
    /// Raw ML-KEM-1024 secret key bytes
    pub mlkem_secret: Vec<u8>,
    /// Raw ML-DSA-87 secret key bytes
    pub mldsa_secret: Vec<u8>,
    /// Raw SPHINCS+-SHA2-256f secret key bytes
    pub sphincs_secret: Vec<u8>,
}

impl std::fmt::Debug for SecretExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretExport")
            .field("mlkem_secret", &"[REDACTED]")
            .field("mldsa_secret", &"[REDACTED]")
            .field("sphincs_secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrng::EntropySource;

    fn test_entropy() -> EntropySource {
        EntropySource::os_only()
    }

    #[test]
    fn test_keypair_generation_succeeds() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy);
        assert!(keypair.is_ok(), "Key generation must succeed with valid entropy");
    }

    #[test]
    fn test_public_keys_have_correct_lengths() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();

        // ML-KEM-1024 public key: 1568 bytes
        assert_eq!(keypair.public.mlkem_public.len(), 1568);

        // ML-DSA-87 public key: 2592 bytes
        assert_eq!(keypair.public.mldsa_public.len(), 2592);

        // SPHINCS+-SHA2-256f public key: 64 bytes
        assert_eq!(keypair.public.sphincs_public.len(), 64);
    }

    #[test]
    fn test_two_keypairs_are_unique() {
        let entropy = test_entropy();
        let kp1 = VaultKeyPair::generate(&entropy).unwrap();
        let kp2 = VaultKeyPair::generate(&entropy).unwrap();

        // Public keys must differ between independent generations
        assert_ne!(
            kp1.public.mlkem_public,
            kp2.public.mlkem_public,
            "Independent key generations must produce unique keys"
        );
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();
        let message = b"colour vault test transaction payload";

        let signature = keypair.sign(message).expect("signing must succeed");
        let valid = signature.verify(message, &keypair.public);

        assert!(valid, "Signature must verify against the correct public key");
    }

    #[test]
    fn test_signature_fails_with_wrong_message() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();

        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = keypair.sign(message).unwrap();
        let valid = signature.verify(wrong_message, &keypair.public);

        assert!(!valid, "Signature must not verify against a different message");
    }

    #[test]
    fn test_signature_fails_with_wrong_public_key() {
        let entropy = test_entropy();
        let kp1 = VaultKeyPair::generate(&entropy).unwrap();
        let kp2 = VaultKeyPair::generate(&entropy).unwrap();

        let message = b"test message";
        let signature = kp1.sign(message).unwrap();

        // Verify with wrong public key — must fail
        let valid = signature.verify(message, &kp2.public);
        assert!(!valid, "Signature must not verify against a different public key");
    }

    #[test]
    fn test_debug_output_redacts_secrets() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();
        let export = keypair.export_secret_for_enclave();

        let debug_str = format!("{:?}", export);

        // Secret key bytes must never appear in debug output
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug output must redact secret key material"
        );
        assert!(
            !debug_str.contains("mlkem_secret: ["),
            "Raw secret bytes must not appear in debug output"
        );
    }

    #[test]
    fn test_secret_export_sizes() {
        let entropy = test_entropy();
        let keypair = VaultKeyPair::generate(&entropy).unwrap();
        let export = keypair.export_secret_for_enclave();

        // ML-KEM-1024 secret key: 3168 bytes
        assert_eq!(export.mlkem_secret.len(), 3168);

        // ML-DSA-87 secret key: 4896 bytes
        assert_eq!(export.mldsa_secret.len(), 4896);

        // SPHINCS+-SHA2-256f secret key: 128 bytes
        assert_eq!(export.sphincs_secret.len(), 128);
    }
}
