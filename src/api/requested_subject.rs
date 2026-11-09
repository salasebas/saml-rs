//! `<EncryptedID>` in the requested `<Subject>` of a received `<AuthnRequest>`.

use crate::entity::EntitySetting;
use crate::flow::FlowResult;

/// `flow` with the `<EncryptedID>` of its requested `<Subject>` replaced by
/// the `<NameID>` it carries, decrypted with the identity provider's
/// decryption key.
///
/// Without a decryption key, for an unauthenticated request whose
/// `EncryptedData` is not AES-GCM, and when decryption fails, `flow` is
/// returned unchanged. Its `<EncryptedID>` then stays unread, and the identity
/// provider answers with an error `<Response>` (Core §3.4.1.4).
pub(super) fn decrypt_requested_subject(
    flow: FlowResult,
    setting: &EntitySetting,
    message_authenticated: bool,
) -> FlowResult {
    match decrypted(&flow, setting, message_authenticated) {
        Ok(Some(decrypted)) => decrypted,
        Ok(None) | Err(_) => flow,
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn decrypted(
    flow: &FlowResult,
    setting: &EntitySetting,
    message_authenticated: bool,
) -> Result<Option<FlowResult>, crate::error::SamlError> {
    use crate::constants::ParserType;
    use crate::crypto::enc::{
        decrypt_authn_request_encrypted_id, AssertionDecryptionOptions, RequestAuthentication,
    };

    let Some(key_pem) = setting.enc_private_key.as_deref() else {
        return Ok(None);
    };
    let authentication = if message_authenticated {
        RequestAuthentication::Authenticated
    } else {
        RequestAuthentication::Unauthenticated
    };
    let key =
        crate::crypto::keys::load_private_key(key_pem, setting.enc_private_key_pass.as_deref())?;
    let Some(saml_content) = decrypt_authn_request_encrypted_id(
        &flow.saml_content,
        &key,
        AssertionDecryptionOptions {
            allow_insecure_software_rsa_key_transport_decryption: setting
                .allow_insecure_software_rsa_key_transport_decryption,
            allow_rsa15_key_transport_decryption: setting.allow_rsa15_key_transport_decryption,
        },
        setting.xml_limits,
        authentication,
    )?
    else {
        return Ok(None);
    };
    crate::context::is_valid_xml_with_limits(&saml_content, setting.xml_limits)?;
    crate::xml::validate_protocol_profile(
        &saml_content,
        ParserType::SamlRequest,
        setting.xml_limits,
    )?;
    let extract = crate::xml::extract_with_limits(
        &saml_content,
        &crate::xml::fields::login_request_fields(),
        setting.xml_limits,
    )?;
    Ok(Some(FlowResult {
        saml_content,
        extract,
        sig_alg: flow.sig_alg.clone(),
    }))
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn decrypted(
    _flow: &FlowResult,
    _setting: &EntitySetting,
    _message_authenticated: bool,
) -> Result<Option<FlowResult>, crate::error::SamlError> {
    Ok(None)
}
