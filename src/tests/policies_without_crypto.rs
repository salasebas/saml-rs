use crate::{ResponseSignaturePolicy, SpValidationPolicy};

/// Recommended, with every field that needs a crypto provider relaxed.
pub(crate) fn sp_validation_without_crypto() -> SpValidationPolicy {
    SpValidationPolicy {
        responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
        ..SpValidationPolicy::default()
    }
}
