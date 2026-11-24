#[cfg(crypto)]
pub(crate) mod enc;
#[cfg(crypto)]
pub(crate) mod keys;
#[cfg(crypto)]
mod provider;
#[cfg(crypto)]
mod response_root;
#[cfg(crypto)]
pub(crate) mod sign;
#[cfg(crypto)]
pub(crate) mod signature_profile;
#[cfg(crypto)]
pub(crate) mod verify;

#[cfg(all(crypto, test))]
pub(crate) use enc::encrypt_assertion;
#[cfg(all(crypto, test, not(feature = "crypto-fips")))]
pub(crate) use enc::{decrypt_assertion_with_limits, AssertionDecryptionOptions};
#[cfg(crypto)]
pub use provider::{
    crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider,
    CryptoProviderInfo,
};
#[cfg(crypto)]
pub(crate) use sign::SigningCredential;
#[cfg(all(crypto, test))]
pub(crate) use sign::{sign_octet_string, sign_saml_xml, verify_octet_string_signature};
#[cfg(all(crypto, test))]
pub(crate) use verify::{verify_signature, verify_signature_with_limits};
