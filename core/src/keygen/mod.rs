use pqcrypto_mlkem::mlkem1024;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_sphincsplus::sphincsshake128fsimple as sphincs;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{
    PublicKey as SignPublicKey,
    SecretKey as SignSecretKey,
    SignedMessage as SignedMessageTrait,
    DetachedSignature,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{VaultError, VaultResult};
use crate::qrng::EntropySource;

#[derive(Debug)]
pub struct VaultKeyPair {
    pub public: PublicComponents,
    secret: SecretComponents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicComponents {
    pub mlkem_public: Vec<u8>,
    pub mldsa_public: Vec<u8>,
    pub sphincs_public: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretComponents {
    mlkem_secret: Vec<u8>,
    mldsa_secret: Vec<u8>,
    sphincs_secret: Vec<u8>,
}

impl std::fmt::Debug for SecretComponents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretComponents")
            .field("mlkem_secret", &"[REDACTED]")
            .field("mldsa_secret", &"[REDACTED]")
            .field("sphincs_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSignature {
    pub mldsa: Vec<u8>,
    pub sphincs: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretExport {
    pub mlkem_secret: Vec<u8>,
    pub mldsa_secret: Vec<u8>,
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

impl VaultKeyPair {
    pub fn generate(entropy: &EntropySource) -> VaultResult<Self> {
        entropy.validate()?;
        let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();
        let (mldsa_pk, mldsa_sk) = mldsa87::keypair();
        let (sphincs_pk, sphincs_sk) = sphincs::keypair();
        Ok(Self {
            public: PublicComponents {
                mlkem_public: mlkem_pk.as_bytes().to_vec(),
                mldsa_public: mldsa_pk.as_bytes().to_vec(),
                sphincs_public: sphincs_pk.as_bytes().to_vec(),
            },
            secret: SecretComponents {
                mlkem_secret: mlkem_sk.as_bytes().to_vec(),
                mldsa_secret: mldsa_sk.as_bytes().to_vec(),
                sphincs_secret: sphincs_sk.as_bytes().to_vec(),
            },
        })
    }

    pub fn sign(&self, message: &[u8]) -> VaultResult<DualSignature> {
        let mldsa_sk = mldsa87::SecretKey::from_bytes(&self.secret.mldsa_secret)
            .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;
        let sphincs_sk = sphincs::SecretKey::from_bytes(&self.secret.sphincs_secret)
            .map_err(|e| VaultError::KeyGeneration(e.to_string()))?;
        let mldsa_sig = mldsa87::sign(message, &mldsa_sk);
        let sphincs_sig = sphincs::sign(message, &sphincs_sk);
        Ok(DualSignature {
            mldsa: mldsa_sig.as_bytes().to_vec(),
            sphincs: sphincs_sig.as_bytes().to_vec(),
        })
    }

    pub fn export_secret_for_enclave(&self) -> SecretExport {
        SecretExport {
            mlkem_secret: self.secret.mlkem_secret.clone(),
            mldsa_secret: self.secret.mldsa_secret.clone(),
            sphincs_secret: self.secret.sphincs_secret.clone(),
        }
    }
}

impl DualSignature {
    pub fn verify(&self, message: &[u8], public: &PublicComponents) -> bool {
        let mldsa_pk = match mldsa87::PublicKey::from_bytes(&public.mldsa_public) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sphincs_pk = match sphincs::PublicKey::from_bytes(&public.sphincs_public) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let mldsa_signed = match mldsa87::SignedMessage::from_bytes(&self.mldsa) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sphincs_signed = match sphincs::SignedMessage::from_bytes(&self.sphincs) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mldsa_opened = match mldsa87::open(&mldsa_signed, &mldsa_pk) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let sphincs_opened = match sphincs::open(&sphincs_signed, &sphincs_pk) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mldsa_opened == message && sphincs_opened == message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrng::EntropySource;

    #[test]
    fn test_keypair_generation_succeeds() {
        assert!(VaultKeyPair::generate(&EntropySource::os_only()).is_ok());
    }

    #[test]
    fn test_two_keypairs_are_unique() {
        let kp1 = VaultKeyPair::generate(&EntropySource::os_only()).unwrap();
        let kp2 = VaultKeyPair::generate(&EntropySource::os_only()).unwrap();
        assert_ne!(kp1.public.mlkem_public, kp2.public.mlkem_public);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = VaultKeyPair::generate(&EntropySource::os_only()).unwrap();
        let msg = b"colour vault test message";
        let sig = kp.sign(msg).unwrap();
        assert!(sig.verify(msg, &kp.public));
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = VaultKeyPair::generate(&EntropySource::os_only()).unwrap();
        let sig = kp.sign(b"original").unwrap();
        assert!(!sig.verify(b"tampered", &kp.public));
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let kp = VaultKeyPair::generate(&EntropySource::os_only()).unwrap();
        let export = kp.export_secret_for_enclave();
        assert!(format!("{:?}", export).contains("[REDACTED]"));
    }
}
