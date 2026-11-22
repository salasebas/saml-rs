use saml_rs::{
    IdpValidationPolicy, LogoutPolicy, LogoutSignaturePolicy, ResponseSignaturePolicy,
    SpValidationPolicy,
};

fn unsigned_logout() -> LogoutPolicy {
    let mut logout = LogoutPolicy::recommended();
    logout.requests = LogoutSignaturePolicy::AllowUnsigned;
    logout.responses = LogoutSignaturePolicy::AllowUnsigned;
    logout
}

/// Recommended, with every field that needs a crypto provider relaxed.
pub fn sp_validation_without_crypto() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::recommended();
    validation.responses = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
    validation.logout = unsigned_logout();
    validation
}

/// Recommended, with every field that needs a crypto provider relaxed.
pub fn idp_validation_without_crypto() -> IdpValidationPolicy {
    let mut validation = IdpValidationPolicy::recommended();
    validation.logout = unsigned_logout();
    validation
}
