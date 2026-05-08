use aes_gcm::{Aes256Gcm, Nonce as AesNonce, aead::{Aead, KeyInit}};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use chacha20poly1305::aead::{Aead as ChachaAead, KeyInit as ChachaKeyInit};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{VaultError, VaultResult};

const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const DERIVED_KEY_LENGTH: usize = 64;
const AES_NONCE_LENGTH: usize = 12;
const CHACHA_NONCE_LENGTH: usize = 12;
const SALT_LENGTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub salt: Vec<u8>,
    pub aes_nonce: Vec<u8>,
    pub chacha_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    aes_key: [u8; 32],
    chacha_key: [u8; 32],
}

pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> VaultResult<EncryptedBlob> {
    if passphrase.is_empty() { return Err(VaultError::InvalidParameter("passphrase must not be empty".to_string())); }
    let mut salt = [0u8; SALT_LENGTH];
    let mut aes_nonce_bytes = [0u8; AES_NONCE_LENGTH];
    let mut chacha_nonce_bytes = [0u8; CHACHA_NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_bytes);
    OsRng.fill_bytes(&mut chacha_nonce_bytes);
    let keys = derive_keys(passphrase, &salt)?;
    let aes_cipher = Aes256Gcm::new_from_slice(&keys.aes_key).map_err(|e| VaultError::Encryption(e.to_string()))?;
    let inner = aes_cipher.encrypt(AesNonce::from_slice(&aes_nonce_bytes), plaintext).map_err(|e| VaultError::Encryption(e.to_string()))?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&keys.chacha_key).map_err(|e| VaultError::Encryption(e.to_string()))?;
    let outer = chacha_cipher.encrypt(ChaChaNonce::from_slice(&chacha_nonce_bytes), inner.as_ref()).map_err(|e| VaultError::Encryption(e.to_string()))?;
    Ok(EncryptedBlob { salt: salt.to_vec(), aes_nonce: aes_nonce_bytes.to_vec(), chacha_nonce: chacha_nonce_bytes.to_vec(), ciphertext: outer })
}

pub fn decrypt(blob: &EncryptedBlob, passphrase: &[u8]) -> VaultResult<Vec<u8>> {
    if passphrase.is_empty() { return Err(VaultError::Decryption); }
    let keys = derive_keys(passphrase, &blob.salt).map_err(|_| VaultError::Decryption)?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&keys.chacha_key).map_err(|_| VaultError::Decryption)?;
    let inner = chacha_cipher.decrypt(ChaChaNonce::from_slice(&blob.chacha_nonce), blob.ciphertext.as_ref()).map_err(|_| VaultError::Decryption)?;
    let aes_cipher = Aes256Gcm::new_from_slice(&keys.aes_key).map_err(|_| VaultError::Decryption)?;
    aes_cipher.decrypt(AesNonce::from_slice(&blob.aes_nonce), inner.as_ref()).map_err(|_| VaultError::Decryption)
}

fn derive_keys(passphrase: &[u8], salt: &[u8]) -> VaultResult<DerivedKeys> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(DERIVED_KEY_LENGTH)).map_err(|e| VaultError::KeyGeneration(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = vec![0u8; DERIVED_KEY_LENGTH];
    argon2.hash_password_into(passphrase, salt, &mut derived).map_err(|e| VaultError::KeyGeneration(e.to_string()))?;
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
    const PASS: &[u8] = b"correct horse battery staple test";
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plain = b"sensitive vault data";
        assert_eq!(plain, decrypt(&encrypt(plain, PASS).unwrap(), PASS).unwrap().as_slice());
    }
    #[test]
    fn test_wrong_passphrase_fails() {
        assert!(decrypt(&encrypt(b"data", PASS).unwrap(), b"wrong").is_err());
    }
    #[test]
    fn test_ciphertext_differs_each_time() {
        assert_ne!(encrypt(b"same", PASS).unwrap().ciphertext, encrypt(b"same", PASS).unwrap().ciphertext);
    }
    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut blob = encrypt(b"data", PASS).unwrap();
        blob.ciphertext[10] ^= 0xFF;
        assert!(decrypt(&blob, PASS).is_err());
    }
    #[test]
    fn test_empty_passphrase_rejected() {
        assert!(encrypt(b"data", b"").is_err());
    }
}
