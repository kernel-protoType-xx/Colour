//! Entropy sourcing for key generation.
//!
//! This module provides the `EntropySource` type, which abstracts over
//! the OS CSPRNG and optional external quantum random number sources.
//!
//! ## Design
//!
//! All key generation in Colour Vault flows through `EntropySource`.
//! The OS CSPRNG (`getrandom`) is always used as the primary source.
//! External QRNG data, when available, is mixed in using BLAKE3 XOF
//! to add additional entropy without reducing the entropy of the OS source.
//!
//! Mixing strategy: `final_entropy = BLAKE3(os_entropy || qrng_entropy)`
//!
//! This is a conservative construction. If the QRNG is compromised or
//! returns weak output, the OS entropy still provides the baseline security.
//!
//! ## QRNG Sources
//!
//! - ANU Quantum Random Numbers (https://qrng.anu.edu.au)
//! - NIST Randomness Beacon (https://beacon.nist.gov)
//!
//! QRNG sources are optional. The vault operates correctly without them.

use getrandom::getrandom;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VaultError, VaultResult};

/// Minimum entropy pool size in bytes.
const MIN_ENTROPY_BYTES: usize = 64;

/// An entropy source for key generation.
///
/// Always includes OS CSPRNG entropy. Optionally mixes in QRNG data.
#[derive(ZeroizeOnDrop)]
pub struct EntropySource {
    /// Combined entropy pool, zeroized on drop
    #[zeroize(skip)]
    source_type: SourceType,
    pool: Vec<u8>,
}

#[derive(Debug)]
enum SourceType {
    OsOnly,
    OsAndQrng,
}

impl EntropySource {
    /// Create an entropy source backed by the OS CSPRNG only.
    ///
    /// This is the standard mode. The OS CSPRNG on Linux, macOS, iOS,
    /// and Android is cryptographically secure and suitable for key
    /// generation without additional sources.
    pub fn os_only() -> Self {
        let mut pool = vec![0u8; MIN_ENTROPY_BYTES];
        // This will panic in tests if getrandom is unavailable.
        // In production, callers should handle this via `try_os_only`.
        getrandom(&mut pool).expect("OS CSPRNG must be available");

        Self {
            source_type: SourceType::OsOnly,
            pool,
        }
    }

    /// Create an entropy source backed by OS CSPRNG plus external QRNG data.
    ///
    /// The QRNG bytes are mixed with OS entropy via BLAKE3. If `qrng_bytes`
    /// is empty, falls back to OS-only mode.
    ///
    /// # Parameters
    ///
    /// - `qrng_bytes`: Raw bytes from a quantum random number source.
    ///   Must be at least 32 bytes for meaningful contribution.
    pub fn with_qrng(qrng_bytes: &[u8]) -> VaultResult<Self> {
        if qrng_bytes.is_empty() {
            return Ok(Self::os_only());
        }

        let mut os_bytes = vec![0u8; MIN_ENTROPY_BYTES];
        getrandom(&mut os_bytes)
            .map_err(|e| VaultError::EntropyFailure(e.to_string()))?;

        // Mix OS entropy and QRNG via BLAKE3
        // If QRNG is weak, OS entropy dominates. Safe construction.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&os_bytes);
        hasher.update(qrng_bytes);

        let mut pool = vec![0u8; MIN_ENTROPY_BYTES];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut pool);

        os_bytes.zeroize();

        Ok(Self {
            source_type: SourceType::OsAndQrng,
            pool,
        })
    }

    /// Validate that the entropy pool is ready for key generation.
    ///
    /// Runs basic statistical checks. These are not a substitute for
    /// proper entropy estimation but catch obvious failures (all zeros,
    /// all same byte, etc.).
    pub fn validate(&self) -> VaultResult<()> {
        if self.pool.len() < MIN_ENTROPY_BYTES {
            return Err(VaultError::EntropyFailure(
                "entropy pool too small".to_string(),
            ));
        }

        // Check for degenerate entropy — all zeros or all same byte
        let first = self.pool[0];
        if self.pool.iter().all(|&b| b == first) {
            return Err(VaultError::EntropyFailure(
                "entropy pool appears degenerate".to_string(),
            ));
        }

        Ok(())
    }

    /// Return a reference to the entropy pool bytes.
    ///
    /// # Auditor Note
    ///
    /// The returned slice is only valid for the lifetime of `self`.
    /// The pool is zeroized when `self` is dropped.
    pub fn pool(&self) -> &[u8] {
        &self.pool
    }

    /// Whether this source includes QRNG data
    pub fn has_qrng(&self) -> bool {
        matches!(self.source_type, SourceType::OsAndQrng)
    }
}

impl std::fmt::Debug for EntropySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntropySource")
            .field("source_type", &self.source_type)
            .field("pool", &"[REDACTED]")
            .field("pool_len", &self.pool.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_entropy_is_valid() {
        let source = EntropySource::os_only();
        assert!(source.validate().is_ok());
    }

    #[test]
    fn test_two_entropy_sources_differ() {
        let s1 = EntropySource::os_only();
        let s2 = EntropySource::os_only();
        assert_ne!(
            s1.pool(),
            s2.pool(),
            "Two independent entropy draws must differ"
        );
    }

    #[test]
    fn test_qrng_mixing() {
        let qrng_bytes = vec![0xAB; 64];
        let source = EntropySource::with_qrng(&qrng_bytes).unwrap();
        assert!(source.validate().is_ok());
        assert!(source.has_qrng());
    }

    #[test]
    fn test_degenerate_entropy_rejected() {
        let mut source = EntropySource::os_only();
        // Force a degenerate pool to test validation
        source.pool.fill(0x00);
        assert!(
            source.validate().is_err(),
            "All-zero entropy pool must be rejected"
        );
    }

    #[test]
    fn test_debug_redacts_pool() {
        let source = EntropySource::os_only();
        let debug = format!("{:?}", source);
        assert!(debug.contains("[REDACTED]"));
    }
  }
