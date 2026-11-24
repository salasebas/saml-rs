use crate::{ResponseSignaturePolicy, SpValidationPolicy};

pub(crate) fn sp_validation_without_crypto() -> SpValidationPolicy {
    SpValidationPolicy {
        response_signatures: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
        ..SpValidationPolicy::default()
    }
}
