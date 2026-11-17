//! Caller-supplied schema validation at inbound XML boundaries.

use crate::SamlError;

/// A schema validator that rejects XML by returning an error reason.
///
/// The callback receives a complete peer document after baseline parser checks,
/// including SOAP envelopes and protocol documents after decryption. It must
/// support the schemas for every input used by the configured role. It can run
/// more than once per operation and must not rely on call counts.
/// No callback is installed by default. Built-in protocol checks always run.
pub type SchemaValidator = fn(&str) -> Result<(), String>;

pub(crate) fn validator_addresses_equal(
    left: Option<SchemaValidator>,
    right: Option<SchemaValidator>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => std::ptr::fn_addr_eq(left, right),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

pub(crate) fn validate(xml: &str, validator: Option<SchemaValidator>) -> Result<(), SamlError> {
    if let Some(validate) = validator {
        validate(xml).map_err(SamlError::Invalid)?;
    }
    Ok(())
}

pub(crate) fn document(
    xml: &str,
    limits: crate::XmlLimits,
    validator: Option<SchemaValidator>,
) -> Result<crate::xml::dom::Document, SamlError> {
    let document = crate::xml::dom::parse_document(xml, limits)?;
    validate(xml, validator)?;
    Ok(document)
}
