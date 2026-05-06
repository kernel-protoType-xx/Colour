//! # Colour Vault Core
//!
//! Post-quantum resistant cryptographic vault core library.
//!
//! This library implements the cryptographic primitives underpinning the
//! Colour Vault protocol. All key material is handled via zeroizing types
//! and constant-time operations to mitigate side-channel attacks.
//!
//! ## Security Model
//!
//! - Private keys never leave the enclave abstraction layer
//! - All sensitive types implement `Zeroize` and `Drop` to clear memory
//! - No cryptographic operations are implemented from scratch — only
//!   well-audited, NIST-standardised libraries are used
//! - Randomness is sourced from the OS CSPRNG via `getrandom`
//!
//! ## Assumptions
//!
//! - The operating system CSPRNG is trustworthy
//! - The hardware secure enclave (where available) is trustworthy
//! - The Rust compiler does not optimise out `zeroize` calls
//!
//! ## What This Library Does NOT Claim
//!
//! - This library has not yet undergone independent third-party audit
//! - "Post-quantum resistant" means resistant to known quantum algorithms
//!   (Shor's, Grover's) against the specified parameter sets — it does not
//!   mean resistance to unknown future attacks
//! - Security claims are bounded by the security of the underlying
//!   NIST-standardised primitives

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::cargo)]
#![allow(clippy::module_name_repetitions)]

pub mod encryption;
pub mod error;
pub mod keygen;
pub mod memory;
pub mod recovery;
pub mod replay;
pub mod rotation;
pub mod signing;
pub mod chains;
pub mod provenance;
pub mod qrng;

/// Re-export the primary vault interface
pub use crate::keygen::VaultKeyPair;
pub use crate::error::VaultError;
pub use crate::recovery::ShamirRecovery;
pub use crate::chains::Chain;
