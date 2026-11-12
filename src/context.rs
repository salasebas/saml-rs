//! Global parsing context and optional schema validation.
//!
//! The [`crate::xml::dom`] parser rejects DOCTYPEs and malformed structures.
//! [`is_valid_xml`] always runs that baseline hardening; a registered schema
//! validator is optional defense in depth.

use crate::error::SamlError;
use crate::xml::XmlLimits;
use std::sync::RwLock;

/// A schema validator: returns `Err(reason)` to reject the XML.
pub type SchemaValidator = fn(&str) -> Result<(), String>;

static SCHEMA_VALIDATOR: RwLock<Option<SchemaValidator>> = RwLock::new(None);

/// Register a schema validator run by [`is_valid_xml`].
pub fn set_schema_validator(validator: SchemaValidator) {
    if let Ok(mut guard) = SCHEMA_VALIDATOR.write() {
        *guard = Some(validator);
    }
}

/// Validate XML: baseline hardening (always) plus the registered validator (if any).
pub fn is_valid_xml(xml: &str) -> Result<(), SamlError> {
    is_valid_xml_with_limits(xml, XmlLimits::default())
}

/// Validate XML with explicit parser resource limits.
pub fn is_valid_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<(), SamlError> {
    validated_document_with_limits(xml, limits).map(|_| ())
}

pub(crate) fn validated_document_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<crate::xml::dom::Document, SamlError> {
    let document = crate::xml::dom::parse_with_limits(xml, limits)?;
    if let Ok(guard) = SCHEMA_VALIDATOR.read() {
        if let Some(validate) = *guard {
            validate(xml).map_err(SamlError::Invalid)?;
        }
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_rejects_doctype_without_validator() {
        assert!(is_valid_xml("<!DOCTYPE x><x/>").is_err());
        assert!(is_valid_xml("<x>ok</x>").is_ok());
    }
}
