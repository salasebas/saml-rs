//! `bergshamra`-backed XML security for the selected provider feature.

use crate::config::XmlSignatureProfile;
#[allow(deprecated)]
use crate::crypto::backend::XmlSecurityBackend;
use crate::crypto::verify::verify_first_signature_with_profile;
use crate::error::{SamlError, SignatureVerificationReason};
use crate::xml::XmlLimits;

/// [`XmlSecurityBackend`] implementation backed by the `bergshamra` crate.
///
/// Verifies enveloped XML-DSig signatures against a metadata certificate using
/// `trusted_keys_only` + `strict_verification` (see [`crate::crypto::verify`]).
/// Success requires coverage of the document root or the direct assertions in
/// a protocol response, as described by [`crate::crypto::verify_signature`].
#[deprecated(
    note = "`saml_rs::crypto` becomes crate-private in the next minor release, and nothing in saml-rs is generic over this trait. The typed API verifies the signatures it receives. To verify other XML, use `bergshamra` directly"
)]
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BergshamraBackend;

#[allow(deprecated)]
impl XmlSecurityBackend for BergshamraBackend {
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError> {
        match verify_first_signature_with_profile(
            xml,
            &[cert_pem.to_string()],
            XmlLimits::default(),
            XmlSignatureProfile::AllowWeakAlgorithms,
        )? {
            (true, Some(_)) => Ok(()),
            (true, None) => Err(SamlError::SignedReferenceMismatch),
            (false, _) => Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::XmlSignature,
            }),
        }
    }
}
