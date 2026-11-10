//! XML security backend abstraction.
//!
//! XML-DSig / XML-Enc / C14N live in `bergshamra`; `saml-rs` only orchestrates
//! through the [`XmlSecurityBackend`] trait.

mod backend;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod bergshamra;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub mod enc;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub mod keys;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod provider;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod response_root;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub mod sign;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub(crate) mod signature_profile;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub mod verify;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod xml_syntax;

pub use backend::XmlSecurityBackend;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use bergshamra::BergshamraBackend;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use enc::{
    decrypt_assertion, decrypt_assertion_with_limits, encrypt_assertion, AssertionDecryptionOptions,
};
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use provider::{
    crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider,
    CryptoProviderInfo,
};
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub(crate) use sign::SigningCredential;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use sign::{construct_message_signature, construct_saml_signature, verify_message_signature};
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use verify::{
    verify_metadata_signature, verify_metadata_signature_detailed,
    verify_metadata_signature_detailed_with_limits, verify_metadata_signature_with_limits,
    verify_signature, verify_signature_with_limits, MetadataSignatureVerification,
};
