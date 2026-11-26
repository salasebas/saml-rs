use crate::constants::ParserType;
use crate::entity::EntitySetting;
use crate::error::SamlError;
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
/// Returns an error when the decryption key does not load, or when the
/// decrypted request fails the `XmlPolicy` schema check, an XML limit, or
/// extraction.
pub(super) fn decrypt_requested_subject(
    flow: FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<(FlowResult, Option<ContentFault>), SamlError> {
    let Some(saml_content) = decrypted_content(&flow, setting, authentication)? else {
        return Ok((flow, None));
    };
    crate::schema::document(&saml_content, setting.xml_limits, setting.schema_validator)?;
    match crate::xml::validate_protocol_profile(
        &saml_content,
        ParserType::SamlRequest,
        setting.xml_limits,
    ) {
        Ok(()) => {}
        Err(error @ SamlError::ProtocolProfile(_)) => {
            return Ok((flow, Some(ContentFault::Malformed(error))));
        }
        Err(error) => return Err(error),
    }
    let extract = crate::xml::extract_with_limits(
        &saml_content,
        &crate::xml::fields::login_request_fields(),
        setting.xml_limits,
    )?;
    let decrypted = FlowResult {
        saml_content,
        extract,
        sig_alg: flow.sig_alg.clone(),
    };
    Ok((decrypted, None))
}

#[cfg(crypto)]
fn decrypted_content(
    flow: &FlowResult,
    setting: &EntitySetting,
    authentication: MessageAuthentication,
) -> Result<Option<String>, SamlError> {
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
) -> Result<Option<String>, SamlError> {
    Ok(None)
}
