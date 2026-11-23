//! `<EncryptedID>` in place of the `<NameID>` of a `<LogoutRequest>`.

use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::metadata::Metadata;
use crate::model::LogoutRequest;
use crate::xml::protocol_element::SamlElement;

/// `xml` with its `<NameID>` encrypted for the peer when `policy` selects it.
/// The peer key is the first `KeyDescriptor` with `use="encryption"` in
/// `target_meta`.
pub(super) fn encrypt_name_id_for_peer(
    xml: String,
    policy: IdentifierEncryptionPolicy,
    init_setting: &EntitySetting,
    target_meta: &Metadata,
) -> Result<String, SamlError> {
    match policy {
        IdentifierEncryptionPolicy::PlaintextIdentifiers => Ok(xml),
        IdentifierEncryptionPolicy::EncryptIdentifiers => {
            let certificate = target_meta
                .x509_certificates(CertUse::Encryption)
                .first()
                .ok_or_else(|| SamlError::MissingMetadata("encryption certificate".into()))?;
            encrypt(&xml, certificate, init_setting)
        }
    }
}

#[cfg(crypto)]
fn encrypt(xml: &str, certificate: &str, setting: &EntitySetting) -> Result<String, SamlError> {
    crate::crypto::enc::encrypt_logout_request_name_id(
        xml,
        certificate,
        &setting.data_encryption_algorithm,
        crate::crypto::enc::KeyTransport::from_setting(setting),
    )
}

#[cfg(not(crypto))]
fn encrypt(_xml: &str, _certificate: &str, _setting: &EntitySetting) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML encryption requires a crypto provider feature".into(),
    ))
}

/// `request` with the `<EncryptedID>` of its `<LogoutRequest>` replaced by
/// the `<NameID>` it carries, decrypted with the local decryption key.
///
/// Call after authenticating the request. If the request has no encrypted
/// identifier, no configured key can decrypt it, or it decrypts to a
/// `<BaseID>`, return the original request.
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
    LogoutRequest::from_flow(
        FlowResult {
            saml_content,
            extract,
            sig_alg: flow.sig_alg.clone(),
        },
        request.reason().map(str::to_owned),
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
