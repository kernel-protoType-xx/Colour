//! Symmetric encryption for vault data at rest.
//!
//! This module implements double encryption using two independent AEAD ciphers:
//!
//! - **AES-256-GCM** — hardware-accelerated on most platforms
//! - **ChaCha20-Poly1305** — software-based, immune to cache-timing attacks
//!
//! Data is encrypted with AES-256-GCM first, then the ciphertext is encrypted
//! again with ChaCha20-Poly1305. Both keys are derived independently from the
//! master key material using Argon2id.
//!
//! This construction means an attacker must break both ciphers simultaneously.
//! It also means the vault remains secure if a weakness is discovered in either
//! cipher independently.
//!
//! ## Key Derivation
//!
//! Keys are derived from a passphrase using Argon2id with the following parameters:
//!
//! - Memory: 64 MiB (m = 65536)
//! - Iterations: 3
//! - Parallelism: 4
//! - Output: 64 bytes (split into two 32-byte keys)
//!
//! These parameters exceed the OWASP minimum recommendations and are calibrated
//! to be slow enough to resist brute force while usable on low-end hardware.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::Aead as ChachaAead, ChaCha20Poly1305, KeyInit as ChachaKeyInit,
    Nonce as ChaChaNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};

/// Argon2id memory parameter: 64 MiB
const ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id iteration count
const ARGON2_ITERATIONS: u32 = 3;
/// Argon2id parallelism
const ARGON2_PARALLELISM: u32 = 4;
/// Total derived key length: 64 bytes (split into two 32-byte keys)
const DERIVED_KEY_LENGTH: usize = 64;
/// AES-GCM nonce length: 12 bytes
const AES_NONCE_LENGTH: usize = 12;
/// ChaCha20 nonce length: 12 bytes
const CHACHA_NONCE_LENGTH: usize = 12;
/// Salt length: 32 bytes
const SALT_LENGTH: usize = 32;

/// A double-encrypted ciphertext blob.
///
/// The outer layer is ChaCha20-Poly1305.
/// The inner layer (recovered after outer decryption) is AES-256-GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Argon2id salt used for key derivation
    pub salt: Vec<u8>,
    /// AES-256-GCM nonce
    pub aes_nonce: Vec<u8>,
    /// ChaCha20-Poly1305 nonce
    pub chacha_nonce: Vec<u8>,
    /// Double-encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

/// Derived encryption keys — zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    /// AES-256-GCM key (32 bytes)
    aes_key: [u8; 32],
    /// ChaCha20-Poly1305 key (32 bytes)
    chacha_key: [u8; 32],
}

/// Encrypt `plaintext` using double AEAD encryption.
///
/// A fresh random salt and nonces are generated for each encryption.
/// The caller must store the returned `EncryptedBlob` to decrypt later.
///
/// # Parameters
///
/// - `plaintext`: The data to encrypt. This is not modified.
/// - `passphrase`: The passphrase for key derivation. Must not be empty.
///
/// # Errors
///
/// Returns `VaultError::Encryption` if any step fails.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> VaultResult<EncryptedBlob> {
    if passphrase.is_empty() {
        return Err(VaultError::InvalidParameter(
            "passphrase must not be empty".to_string(),
        ));
    }

    // Generate fresh random salt and nonces
    let mut salt = [0u8; SALT_LENGTH];
    let mut aes_nonce_bytes = [0u8; AES_NONCE_LENGTH];
    let mut chacha_nonce_bytes = [0u8; CHACHA_NONCE_LENGTH];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_bytes);
    OsRng.fill_bytes(&mut chacha_nonce_bytes);

    // Derive two independent keys from the passphrase
    let keys = derive_keys(passphrase, &salt)?;

    // Layer 1: AES-256-GCM encryption
    let aes_cipher = Aes256Gcm::new_from_slice(&keys.aes_key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let aes_nonce = AesNonce::from_slice(&aes_nonce_bytes);
    let inner_ciphertext = aes_cipher
        .encrypt(aes_nonce, plaintext)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    // Layer 2: ChaCha20-Poly1305 encryption of the AES ciphertext
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&keys.chacha_key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let chacha_nonce = ChaChaNonce::from_slice(&chacha_nonce_bytes);
    let outer_ciphertext = chacha_cipher
        .encrypt(chacha_nonce, inner_ciphertext.as_ref())
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    Ok(EncryptedBlob {
        salt: salt.to_vec(),
        aes_nonce: aes_nonce_bytes.to_vec(),
        chacha_nonce: chacha_nonce_bytes.to_vec(),
        ciphertext: outer_ciphertext,
    })
}

/// Decrypt an `EncryptedBlob` produced by `encrypt`.
///
/// # Errors
///
/// Returns `VaultError::Decryption` on any failure. The error is
/// deliberately opaque to prevent decryption oracle attacks.
pub fn decrypt(blob: &EncryptedBlob, passphrase: &[u8]) -> VaultResult<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(VaultError::Decryption);
    }

    let keys = derive_keys(passphrase, &blob.salt)
        .map_err(|_| VaultError::Decryption)?;

    // Layer 2: Decrypt ChaCha20-Poly1305 outer layer
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&keys.chacha_key)
        .map_err(|_| VaultError::Decryption)?;
    let chacha_nonce = ChaChaNonce::from_slice(&blob.chacha_nonce);
    let inner_ciphertext = chacha_cipher
        .decrypt(chacha_nonce, blob.ciphertext.as_ref())
        .map_err(|_| VaultError::Decryption)?;

    // Layer 1: Decrypt AES-256-GCM inner layer
    let aes_cipher = Aes256Gcm::new_from_slice(&keys.aes_key)
        .map_err(|_| VaultError::Decryption)?;
    let aes_nonce = AesNonce::from_slice(&blob.aes_nonce);
    let plaintext = aes_cipher
        .decrypt(aes_nonce, inner_ciphertext.as_ref())
        .map_err(|_| VaultError::Decryption)?;

    Ok(plaintext)
}

/// Derive two independent 32-byte keys from a passphrase using Argon2id.
fn derive_keys(passphrase: &[u8], salt: &[u8]) -> VaultResult<DerivedKeys> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LENGTH),
    )
    .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived = vec![0u8; DERIVED_KEY_LENGTH];
    argon2
        .hash_password_into(passphrase, salt, &mut derived)
        .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;

    let mut aes_key = [0u8; 32];
    let mut chacha_key = [0u8; 32];

    aes_key.copy_from_slice(&derived[..32]);
    chacha_key.copy_from_slice(&derived[32..]);

    derived.zeroize();

    Ok(DerivedKeys { aes_key, chacha_key })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSPHRASE: &[u8] = b"correct horse battery staple entropy test";

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"sensitive vault key material";
        let blob = encrypt(plaintext, TEST_PASSPHRASE).unwrap();
        let recovered = decrypt(&blob, TEST_PASSPHRASE).unwrap();
        assert_eq!(plaintext, recovered.as_slice());
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"vault secrets";
        let blob = encrypt(plaintext, TEST_PASSPHRASE).unwrap();
        let result = decrypt(&blob, b"wrong passphrase");
        assert!(result.is_err(), "Decryption with wrong passphrase must fail");
    }

    #[test]
    fn test_ciphertext_differs_each_time() {
        let plaintext = b"same plaintext";
        let blob1 = encrypt(plaintext, TEST_PASSPHRASE).unwrap();
        let blob2 = encrypt(plaintext, TEST_PASSPHRASE).unwrap();
        assert_ne!(
            blob1.ciphertext, blob2.ciphertext,
            "Fresh nonces must produce different ciphertexts"
        );
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let plaintext = b"vault key data";
        let mut blob = encrypt(plaintext, TEST_PASSPHRASE).unwrap();

        // Flip a bit in the ciphertext
        blob.ciphertext[10] ^= 0xFF;

        let result = decrypt(&blob, TEST_PASSPHRASE);
        assert!(result.is_err(), "Tampered ciphertext must fail authentication");
    }

    #[test]
    fn test_empty_passphrase_rejected() {
        let plaintext = b"data";
        assert!(encrypt(plaintext, b"").is_err());
    }

    #[test]
    fn test_empty_plaintext_encrypts_correctly() {
        let blob = encrypt(b"", TEST_PASSPHRASE).unwrap();
        let recovered = decrypt(&blob, TEST_PASSPHRASE).unwrap();
        assert_eq!(b"" as &[u8], recovered.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let plaintext = vec![0x42u8; 1_000_000]; // 1 MB
        let blob = encrypt(&plaintext, TEST_PASSPHRASE).unwrap();
        let recovered = decrypt(&blob, TEST_PASSPHRASE).unwrap();
        assert_eq!(plaintext, recovered);
    }
}
