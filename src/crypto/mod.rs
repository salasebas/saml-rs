//! XML security backend abstraction.
//!
//! XML-DSig / XML-Enc / C14N live in `bergshamra`; `saml-rs` only orchestrates
//! through the [`XmlSecurityBackend`] trait.

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
#[cfg(crypto)]
mod xml_syntax;

pub use backend::XmlSecurityBackend;
#[cfg(crypto)]
pub use bergshamra::BergshamraBackend;
#[cfg(crypto)]
pub use enc::{
    decrypt_assertion, decrypt_assertion_with_limits, encrypt_assertion, AssertionDecryptionOptions,
};
#[cfg(crypto)]
pub use provider::{
    crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider,
    CryptoProviderInfo,
};
#[cfg(crypto)]
pub(crate) use sign::SigningCredential;
#[cfg(crypto)]
pub use sign::{construct_message_signature, construct_saml_signature, verify_message_signature};
#[cfg(crypto)]
pub use verify::{
    verify_metadata_signature, verify_metadata_signature_detailed,
    verify_metadata_signature_detailed_with_limits, verify_metadata_signature_with_limits,
    verify_signature, verify_signature_with_limits, MetadataSignatureVerification,
};
