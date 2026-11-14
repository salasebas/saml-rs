//! `bergshamra`-backed XML security for the selected provider feature.

use crate::crypto::backend::XmlSecurityBackend;
use crate::error::SamlError;

/// [`XmlSecurityBackend`] implementation backed by the `bergshamra` crate.
///
/// Verifies enveloped XML-DSig signatures against a metadata certificate using
/// `trusted_keys_only` + `strict_verification` (see [`crate::crypto::verify`]).
/// Success requires coverage of the document root or the direct assertions in
/// a protocol response, as described by [`crate::crypto::verify_signature`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BergshamraBackend;

impl XmlSecurityBackend for BergshamraBackend {
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError> {
        match crate::crypto::verify::verify_signature(xml, &[cert_pem.to_string()])? {
            (true, Some(_)) => Ok(()),
            (true, None) => Err(SamlError::SignedReferenceMismatch),
            (false, _) => Err(SamlError::FailedToVerifySignature),
        }
    }
}
