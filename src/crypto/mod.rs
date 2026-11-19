//! XML signature and encryption for the typed flows.
//!
//! XML-DSig, XML-Enc, and canonicalization live in `bergshamra`; this module
//! calls it directly.

mod backend;
#[cfg(crypto)]
mod bergshamra;
#[cfg(crypto)]
pub mod enc;
#[cfg(crypto)]
pub mod keys;
#[cfg(crypto)]
mod provider;
#[cfg(crypto)]
mod response_root;
#[cfg(crypto)]
pub mod sign;
#[cfg(crypto)]
pub(crate) mod signature_profile;
#[cfg(crypto)]
pub mod verify;

#[allow(deprecated)]
pub use backend::XmlSecurityBackend;
#[cfg(crypto)]
#[allow(deprecated)]
pub use bergshamra::BergshamraBackend;
#[cfg(crypto)]
pub use enc::*;
#[cfg(crypto)]
pub use provider::{
    crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider,
    CryptoProviderInfo,
};
#[cfg(crypto)]
pub(crate) use sign::SigningCredential;
#[cfg(crypto)]
pub use sign::*;
#[cfg(crypto)]
#[allow(deprecated)]
pub use verify::MetadataSignatureVerification;
#[cfg(crypto)]
#[allow(deprecated)]
pub use verify::{
    verify_metadata_signature, verify_metadata_signature_detailed,
    verify_metadata_signature_detailed_with_limits, verify_metadata_signature_with_limits,
    verify_signature, verify_signature_with_limits,
};
