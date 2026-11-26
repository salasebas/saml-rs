use crate::constants::ParserType;
use crate::entity::EntitySetting;
use crate::flow::{FlowResult, MessageAuthentication};
use crate::model::ContentFault;

/// `flow` with the `<EncryptedID>` of its requested `<Subject>` replaced by
/// the `<NameID>` it carries, decrypted with the identity provider's
/// decryption key.
///
/// Without a decryption key, for an unauthenticated request whose
/// `EncryptedData` is not AES-GCM, and when the `<EncryptedID>` does not
/// decrypt to one `<NameID>`, `flow` is returned unchanged. Its
/// `<EncryptedID>` then stays unread, and the identity provider answers with
/// an error `<Response>` (Core §3.4.1.4). When the decrypted request breaks
/// the protocol profile, `flow` is returned unchanged with that fault.
///
/// # Errors
///
/// Returns an error when the decryption key does not load.
pub(super) fn decrypt_requested_subject(
    flow: FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<(FlowResult, Option<ContentFault>), crate::error::SamlError> {
    let Some(saml_content) = decrypted_content(&flow, setting, authentication)? else {
        return Ok((flow, None));
    };
    match decrypted_flow(saml_content, &flow, setting) {
        Ok(decrypted) => Ok((decrypted, None)),
        Err(error) => Ok((flow, Some(ContentFault::malformed(error)))),
    }
}

fn decrypted_flow(
    saml_content: String,
    flow: &FlowResult,
    setting: &EntitySetting,
) -> Result<FlowResult, crate::error::SamlError> {
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
    Ok(FlowResult {
        saml_content,
        extract,
        sig_alg: flow.sig_alg.clone(),
    })
}

#[cfg(crypto)]
fn decrypted_content(
    flow: &FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<Option<String>, crate::error::SamlError> {
    use crate::crypto::enc::decrypt_authn_request_encrypted_id;

    let Some(key_pem) = setting.enc_private_key.as_deref() else {
        return Ok(None);
    };
    decrypt_authn_request_encrypted_id(
        &flow.saml_content,
        key_pem,
        setting.enc_private_key_pass.as_deref(),
        &setting.additional_decryption_keys,
        setting.into(),
        setting.xml_limits,
        authentication,
    )
}

#[cfg(not(crypto))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "The provider implementation can fail and shares this interface"
)]
fn decrypted_content(
    _flow: &FlowResult,
    _setting: &EntitySetting,
    _authentication: MessageAuthentication,
) -> Result<Option<String>, crate::error::SamlError> {
    Ok(None)
}
