//! Automatic annual key rotation for Colour Vault.
//!
//! Keys rotate automatically every 365 days. The user is notified
//! before rotation. The old key signs the new key to prove continuity.
//! No user action is required for the rotation itself.
//!
//! ## Rotation Flow
//!
//! 1. Rotation due date checked on every vault open
//! 2. New key pair generated with fresh entropy
//! 3. Old key signs the new public key (proves continuity)
//! 4. New key encrypted and stored in enclave
//! 5. Old key zeroized
//! 6. Shamir shares regenerated for new key
//! 7. User notified to redistribute shares

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{VaultError, VaultResult};

/// Rotation interval in seconds (365 days)
const ROTATION_INTERVAL_SECS: u64 = 365 * 24 * 60 * 60;

/// Key rotation metadata stored alongside the encrypted vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationMetadata {
    /// Unix timestamp of last rotation
    pub last_rotation: u64,
    /// Unix timestamp of next scheduled rotation
    pub next_rotation: u64,
    /// Rotation count (increments with each rotation)
    pub rotation_count: u32,
}

impl RotationMetadata {
    /// Create initial rotation metadata at vault creation time.
    pub fn new() -> VaultResult<Self> {
        let now = current_timestamp()?;
        Ok(Self {
            last_rotation: now,
            next_rotation: now + ROTATION_INTERVAL_SECS,
            rotation_count: 0,
        })
    }

    /// Check whether rotation is due.
    pub fn is_rotation_due(&self) -> VaultResult<bool> {
        let now = current_timestamp()?;
        Ok(now >= self.next_rotation)
    }

    /// Days remaining until next rotation (0 if overdue)
    pub fn days_until_rotation(&self) -> VaultResult<u64> {
        let now = current_timestamp()?;
        if now >= self.next_rotation {
            return Ok(0);
        }
        let secs_remaining = self.next_rotation - now;
        Ok(secs_remaining / 86_400)
    }

    /// Advance metadata after a completed rotation.
    pub fn record_rotation(&mut self) -> VaultResult<()> {
        let now = current_timestamp()?;
        self.last_rotation = now;
        self.next_rotation = now + ROTATION_INTERVAL_SECS;
        self.rotation_count += 1;
        Ok(())
    }
}

impl Default for RotationMetadata {
    fn default() -> Self {
        Self::new().expect("system clock must be available")
    }
}

fn current_timestamp() -> VaultResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| VaultError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_rotation_not_due() {
        let meta = RotationMetadata::new().unwrap();
        assert!(!meta.is_rotation_due().unwrap());
    }

    #[test]
    fn test_days_until_rotation_near_365() {
        let meta = RotationMetadata::new().unwrap();
        let days = meta.days_until_rotation().unwrap();
        assert!(days >= 364 && days <= 365);
    }

    #[test]
    fn test_record_rotation_increments_count() {
        let mut meta = RotationMetadata::new().unwrap();
        assert_eq!(meta.rotation_count, 0);
        meta.record_rotation().unwrap();
        assert_eq!(meta.rotation_count, 1);
    }

    #[test]
    fn test_overdue_rotation() {
        let mut meta = RotationMetadata::new().unwrap();
        // Force rotation to be overdue
        meta.next_rotation = 0;
        assert!(meta.is_rotation_due().unwrap());
        assert_eq!(meta.days_until_rotation().unwrap(), 0);
    }
}
