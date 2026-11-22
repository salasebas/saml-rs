use crate::{
    IdpValidationPolicy, LogoutPolicy, LogoutSignaturePolicy, ResponseSignaturePolicy,
    SpValidationPolicy,
};

pub(crate) const UNSIGNED_LOGOUT: LogoutPolicy = LogoutPolicy {
    requests: LogoutSignaturePolicy::AllowUnsigned,
    responses: LogoutSignaturePolicy::AllowUnsigned,
};

/// Recommended, with every field that needs a crypto provider relaxed.
pub(crate) fn sp_validation_without_crypto() -> SpValidationPolicy {
    SpValidationPolicy {
        responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
        logout: UNSIGNED_LOGOUT,
        ..SpValidationPolicy::recommended()
    }
}

/// Recommended, with every field that needs a crypto provider relaxed.
pub(crate) fn idp_validation_without_crypto() -> IdpValidationPolicy {
    IdpValidationPolicy {
        logout: UNSIGNED_LOGOUT,
        ..IdpValidationPolicy::recommended()
    }
}
