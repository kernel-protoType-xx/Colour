//! Secure memory management for sensitive key material.
//!
//! This module provides utilities to ensure sensitive data is handled
//! carefully in memory:
//!
//! - Zeroizing wrappers that clear memory on drop
//! - Guards against accidental logging or serialisation of secrets
//!
//! ## Limitations
//!
//! Rust's ownership model and the `zeroize` crate handle most cases well,
//! but there are platform-level limits:
//!
//! - Swap encryption depends on the OS configuration
//! - Core dumps may capture memory if not disabled at the OS level
//! - Compiler optimisations are prevented by `zeroize`'s use of
//!   `write_volatile` and compiler fences
//!
//! Deployments handling significant assets should disable core dumps
//! at the OS level and enable swap encryption.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A buffer holding sensitive bytes that are zeroized when dropped.
///
/// Use this type anywhere temporary sensitive data must be held —
/// for example, during a key derivation step before the result is
/// moved into a permanent zeroizing structure.
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    inner: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity, zeroed.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: vec![0u8; capacity],
        }
    }

    /// Create a secure buffer from existing bytes.
    ///
    /// The original `bytes` vector is consumed and ownership transferred.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Access the buffer contents as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Access the buffer contents as a mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Return the length of the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("len", &self.inner.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Explicitly zeroize a byte slice.
///
/// Prefer using `ZeroizeOnDrop` types. Use this function only when
/// you hold a `&mut [u8]` that cannot be wrapped in a zeroizing type.
pub fn zeroize_slice(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_debug_redacted() {
        let buf = SecureBuffer::from_vec(vec![0xAB; 32]);
        let debug = format!("{:?}", buf);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("AB"));
    }

    #[test]
    fn test_secure_buffer_len() {
        let buf = SecureBuffer::with_capacity(64);
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn test_zeroize_slice() {
        let mut data = vec![0xFF; 32];
        zeroize_slice(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
