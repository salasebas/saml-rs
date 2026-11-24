use crate::entity::EntitySetting;
use crate::flow::{FlowResult, MessageAuthentication};

/// `flow` with the `<EncryptedID>` of its requested `<Subject>` replaced by
/// the `<NameID>` it carries, decrypted with the identity provider's
/// decryption key.
///
/// Without a decryption key, for an unauthenticated request whose
/// `EncryptedData` is not AES-GCM, and when the `<EncryptedID>` does not
/// decrypt to one `<NameID>`, `flow` is returned unchanged. Its
/// `<EncryptedID>` then stays unread, and the identity provider answers with
/// an error `<Response>` (Core §3.4.1.4).
///
/// # Errors
///
/// Returns an error when the decryption key does not load.
pub(super) fn decrypt_requested_subject(
    flow: FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<FlowResult, crate::error::SamlError> {
    Ok(decrypted(&flow, setting, authentication)?.unwrap_or(flow))
}

#[cfg(crypto)]
fn decrypted(
    flow: &FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<Option<FlowResult>, crate::error::SamlError> {
    use crate::constants::ParserType;
    use crate::crypto::enc::decrypt_authn_request_encrypted_id;

    let Some(key_pem) = setting.enc_private_key.as_deref() else {
        return Ok(None);
    };
    let Some(saml_content) = decrypt_authn_request_encrypted_id(
        &flow.saml_content,
        key_pem,
        setting.enc_private_key_pass.as_deref(),
        &setting.additional_decryption_keys,
        setting.into(),
        setting.xml_limits,
        authentication,
    )?
    else {
        return Ok(None);
    };
    crate::schema::document(&saml_content, setting.xml_limits, setting.schema_validator)?;
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

#[cfg(not(crypto))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "The provider implementation can fail and shares this interface"
)]
fn decrypted(
    _flow: &FlowResult,
    _setting: &EntitySetting,
    _authentication: MessageAuthentication,
) -> Result<Option<FlowResult>, crate::error::SamlError> {
    Ok(None)
}
