//! Baseline XML parsing checks.
//!
//! The [`crate::xml::dom`] parser rejects DOCTYPEs and malformed structures.
//! [`is_valid_xml_with_limits`] always runs that baseline hardening; an optional
//! schema validator can be configured through [`crate::XmlPolicy`].

use crate::error::SamlError;
use crate::xml::XmlLimits;

pub use crate::SchemaValidator;

/// Validate XML with baseline parser hardening.
#[deprecated(
    note = "`saml_rs::context` becomes crate-private in the next minor release; the typed API checks every message it receives"
)]
pub fn is_valid_xml(xml: &str) -> Result<(), SamlError> {
    is_valid_xml_with_limits(xml, XmlLimits::default())
}

/// Validate XML with explicit parser resource limits.
pub fn is_valid_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<(), SamlError> {
    crate::xml::dom::parse_document(xml, limits).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        deprecated,
        reason = "the deprecated public check keeps its behaviour until removal"
    )]
    fn baseline_rejects_doctype_without_validator() {
        assert!(is_valid_xml("<!DOCTYPE x><x/>").is_err());
        assert!(is_valid_xml("<x>ok</x>").is_ok());
    }
}
