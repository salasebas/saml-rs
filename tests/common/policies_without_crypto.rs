use saml_rs::{ResponseSignaturePolicy, SpValidationPolicy};

pub fn sp_validation_without_crypto() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::default();
    validation.response_signatures = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
    validation
}
