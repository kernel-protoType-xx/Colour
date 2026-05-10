//! Shamir Secret Sharing for vault recovery.
//!
//! This module implements Shamir's Secret Sharing over GF(256)
//! from scratch, replacing the vulnerable sharks 0.5.0 library
//! (RUSTSEC-2024-0398 — biased polynomial coefficients).
//!
//! Security properties:
//! - Coefficients generated using OsRng — cryptographically secure
//! - No bias in polynomial coefficients
//! - Information-theoretic security below threshold
//! - 3-of-5 threshold scheme

use rand_core::{OsRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::error::{VaultError, VaultResult};

const TOTAL_SHARES: u8 = 5;
const THRESHOLD: u8 = 3;

// GF(256) arithmetic using the AES irreducible polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11b)
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

fn gf256_pow(base: u8, exp: u8) -> u8 {
    let mut result = 1u8;
    for _ in 0..exp {
        result = gf256_mul(result, base);
    }
    result
}

/// Evaluate polynomial at point x in GF(256)
/// coefficients[0] is the secret (constant term)
fn poly_eval(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for (i, &coeff) in coefficients.iter().enumerate() {
        result ^= gf256_mul(coeff, gf256_pow(x, i as u8));
    }
    result
}

/// Lagrange interpolation in GF(256) to recover secret
fn lagrange_interpolate(shares: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    let k = shares.len();
    for i in 0..k {
        let (xi, yi) = shares[i];
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..k {
            if i == j { continue; }
            let (xj, _) = shares[j];
            num = gf256_mul(num, xj);
            den = gf256_mul(den, xi ^ xj);
        }
        // Division in GF(256): multiply by inverse
        // Inverse via Fermat: a^(2^8 - 2) = a^254
        let den_inv = gf256_pow(den, 254);
        secret ^= gf256_mul(gf256_mul(yi, num), den_inv);
    }
    secret
}

/// A single Shamir recovery share.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecoveryShare {
    #[zeroize(skip)]
    index: u8,
    bytes: Vec<u8>,
}

impl RecoveryShare {
    pub fn index(&self) -> u8 { self.index }
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
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

pub struct ShamirRecovery;

impl ShamirRecovery {
    /// Split a secret into TOTAL_SHARES shares.
    /// Any THRESHOLD shares can reconstruct the secret.
    ///
    /// Each byte of the secret is shared independently over GF(256).
    /// Coefficients are generated using OsRng — no bias.
    pub fn split(secret: &[u8]) -> VaultResult<Vec<RecoveryShare>> {
        if secret.is_empty() {
            return Err(VaultError::InvalidParameter(
                "secret must not be empty".to_string()
            ));
        }

        let threshold = THRESHOLD as usize;
        let total = TOTAL_SHARES as usize;

        let mut share_bytes = vec![vec![0u8; secret.len()]; total];

        for (byte_idx, &secret_byte) in secret.iter().enumerate() {
            // Generate threshold-1 random coefficients using OsRng
            // This fixes RUSTSEC-2024-0398 — coefficients are uniform
            let mut coeffs = vec![secret_byte];
            let mut random_bytes = vec![0u8; threshold - 1];
            OsRng.fill_bytes(&mut random_bytes);
            coeffs.extend_from_slice(&random_bytes);

            for i in 0..total {
                let x = (i + 1) as u8;
                share_bytes[i][byte_idx] = poly_eval(&coeffs, x);
            }
        }

        let shares = share_bytes
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| RecoveryShare {
                index: (i + 1) as u8,
                bytes,
            })
            .collect();

        Ok(shares)
    }

    /// Reconstruct secret from at least THRESHOLD shares.
    pub fn reconstruct(shares: &[RecoveryShare]) -> VaultResult<Vec<u8>> {
        if shares.len() < THRESHOLD as usize {
            return Err(VaultError::InsufficientShares {
                needed: THRESHOLD,
                provided: shares.len(),
            });
        }

        let secret_len = shares[0].bytes.len();

        for share in shares {
            if share.bytes.len() != secret_len {
                return Err(VaultError::SecretSharing(
                    "share length mismatch".to_string()
                ));
            }
        }

        let mut secret = vec![0u8; secret_len];

        for byte_idx in 0..secret_len {
            let points: Vec<(u8, u8)> = shares
                .iter()
                .take(THRESHOLD as usize)
                .map(|s| (s.index, s.bytes[byte_idx]))
                .collect();
            secret[byte_idx] = lagrange_interpolate(&points);
        }

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test secret data must be long enough ok";

    #[test]
    fn test_split_produces_five_shares() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_reconstruct_with_all_five_shares() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        let recovered = ShamirRecovery::reconstruct(&shares).unwrap();
        assert_eq!(SECRET, recovered.as_slice());
    }

    #[test]
    fn test_reconstruct_with_three_shares() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        let subset = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ];
        let recovered = ShamirRecovery::reconstruct(&subset).unwrap();
        assert_eq!(SECRET, recovered.as_slice());
    }

    #[test]
    fn test_reconstruct_different_three_shares() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        let subset = vec![
            shares[1].clone(),
            shares[2].clone(),
            shares[3].clone(),
        ];
        let recovered = ShamirRecovery::reconstruct(&subset).unwrap();
        assert_eq!(SECRET, recovered.as_slice());
    }

    #[test]
    fn test_two_shares_insufficient() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        assert!(ShamirRecovery::reconstruct(&subset).is_err());
    }

    #[test]
    fn test_shares_are_unique() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(shares[i].bytes, shares[j].bytes);
            }
        }
    }

    #[test]
    fn test_debug_redacts_bytes() {
        let shares = ShamirRecovery::split(SECRET).unwrap();
        let debug = format!("{:?}", shares[0]);
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_gf256_mul_identity() {
        for i in 1..=255u8 {
            assert_eq!(super::gf256_mul(i, 1), i);
        }
    }

    #[test]
    fn test_gf256_inverse() {
        for i in 1..=255u8 {
            let inv = super::gf256_pow(i, 254);
            assert_eq!(super::gf256_mul(i, inv), 1);
        }
    }
        }
