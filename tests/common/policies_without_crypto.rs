use saml_rs::{ResponseSignaturePolicy, SpValidationPolicy};

/// Recommended, with every field that needs a crypto provider relaxed.
pub fn sp_validation_without_crypto() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::default();
    validation.responses = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
    validation
}
