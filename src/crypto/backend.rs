//! XML security backend trait.

use crate::error::SamlError;

/// XML signature verifier implemented by `BergshamraBackend`.
///
/// No saml-rs operation takes an implementation.
#[deprecated(
    note = "`saml_rs::crypto` becomes crate-private in the next minor release, and nothing in saml-rs is generic over this trait. The typed API verifies the signatures it receives. To verify other XML, use `bergshamra` directly"
)]
pub trait XmlSecurityBackend {
    /// Verify an enveloped XML-DSig signature over `xml` using `cert_pem`.
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError>;
}
