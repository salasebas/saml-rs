//! The `<Issuer>` of a login `<Response>`, compared with the identity provider
//! whatever the response status.

use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{extract_with_limits, ExtractorField, XmlLimits};

pub(super) fn validate_response_issuer(
    expected: &str,
    xml: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let issuer = [ExtractorField::new("issuer", &["Response", "Issuer"])];
    let extracted = extract_with_limits(xml, &issuer, limits)?;
    match extracted.get("issuer") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(actual)) if actual == expected => Ok(()),
        Some(Value::Str(actual)) => Err(SamlError::issuer_mismatch(expected, Some(actual))),
        Some(Value::Array(_) | Value::Object(_)) => Err(SamlError::issuer_mismatch(expected, None)),
    }
}
