use crate::config::IdentifierEncryptionPolicy;
use crate::constants::ParserType;
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::metadata::Metadata;
use crate::model::LogoutRequest;
use crate::xml::protocol_element::SamlElement;

pub(super) fn encrypt_name_id_for_peer(
    xml: String,
    policy: IdentifierEncryptionPolicy,
    init_setting: &EntitySetting,
    target_meta: &Metadata,
) -> Result<String, SamlError> {
    match policy {
        IdentifierEncryptionPolicy::PlaintextIdentifiers => Ok(xml),
        IdentifierEncryptionPolicy::EncryptIdentifiers => encrypt(&xml, init_setting, target_meta),
    }
}

#[cfg(crypto)]
fn encrypt(xml: &str, setting: &EntitySetting, peer: &Metadata) -> Result<String, SamlError> {
    use crate::crypto::enc::{encrypt_logout_request_name_id, EncryptionRecipient};

    encrypt_logout_request_name_id(
        xml,
        &EncryptionRecipient::from_setting(peer.encryption_key_certificates(), setting),
    )
}

#[cfg(not(crypto))]
fn encrypt(_xml: &str, _setting: &EntitySetting, _peer: &Metadata) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML encryption requires a crypto provider feature".into(),
    ))
}

pub(crate) fn decrypt_encrypted_id(
    request: LogoutRequest,
    setting: &EntitySetting,
    document: &SamlElement,
) -> Result<LogoutRequest, SamlError> {
    let Some(key_pem) = setting.enc_private_key.as_deref() else {
        return Ok(request);
    };
    let flow = request.raw_flow();
    let carries_encrypted_id = document
        .children
        .iter()
        .any(|child| child.local_name == "EncryptedID");
    if !carries_encrypted_id {
        return Ok(request);
    }
    let Some(saml_content) = decrypt(&flow.saml_content, key_pem, setting)? else {
        return Ok(request);
    };
    crate::schema::document(&saml_content, setting.xml_limits, setting.schema_validator)?;
    crate::xml::validate_protocol_profile(
        &saml_content,
        ParserType::LogoutRequest,
        setting.xml_limits,
    )?;
    let extract = crate::xml::extract_with_limits(
        &saml_content,
        &crate::xml::fields::logout_request_fields(),
        setting.xml_limits,
    )?;
    if extract
        .get_str(crate::xml::fields::name_id::VALUE)
        .is_none()
    {
        return Ok(request);
    }
    let reason = request.reason().map(str::to_owned);
    LogoutRequest::from_flow(
        FlowResult {
            saml_content,
            extract,
            sig_alg: flow.sig_alg.clone(),
        },
        reason,
    )
}

#[cfg(crypto)]
fn decrypt(xml: &str, key_pem: &str, setting: &EntitySetting) -> Result<Option<String>, SamlError> {
    use crate::crypto::enc::decrypt_logout_request_encrypted_id;

    let keys = crate::crypto::keys::load_decryption_keys(
        key_pem,
        setting.enc_private_key_pass.as_deref(),
        &setting.additional_decryption_keys,
    )?;
    decrypt_logout_request_encrypted_id(xml, &keys, setting.into(), setting.xml_limits)
}

#[cfg(not(crypto))]
fn decrypt(_: &str, _: &str, _: &EntitySetting) -> Result<Option<String>, SamlError> {
    Err(SamlError::Unsupported(
        "XML decryption requires a crypto provider feature".into(),
    ))
}
