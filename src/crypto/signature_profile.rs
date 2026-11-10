//! The signature and digest algorithms each [`XmlSignatureProfile`] accepts on
//! a signature that authenticates an accepted message.

use crate::config::XmlSignatureProfile;
use crate::constants::{digest_algorithm, signature_algorithm};

/// Whether `profile` accepts the XML-DSig `SignatureMethod` or detached
/// `SigAlg` URI.
pub(crate) fn allows_signature_method(profile: XmlSignatureProfile, uri: &str) -> bool {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 => matches!(
            uri,
            signature_algorithm::RSA_SHA256
                | signature_algorithm::RSA_SHA384
                | signature_algorithm::RSA_SHA512
        ),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => true,
    }
}

/// Whether `profile` accepts the XML-DSig `DigestMethod` URI of a reference.
pub(crate) fn allows_digest_method(profile: XmlSignatureProfile, uri: &str) -> bool {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 => matches!(
            uri,
            digest_algorithm::SHA256 | digest_algorithm::SHA384 | digest_algorithm::SHA512
        ),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => true,
    }
}
