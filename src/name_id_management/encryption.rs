use crate::config::IdentifierEncryptionPolicy;
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::NameId;
use crate::xml::protocol_element::parse_saml_with_limits;

use super::{identifier_and_change, Change, Identifier, NameIdChange};

#[derive(Debug, Clone, Copy)]
enum EncryptedChild {
    EncryptedId,
    NewEncryptedId,
}

pub(crate) fn protect_request(
    xml: String,
    policy: IdentifierEncryptionPolicy,
    setting: &EntitySetting,
    peer: &Metadata,
) -> Result<String, SamlError> {
    match policy {
        IdentifierEncryptionPolicy::PlaintextIdentifiers => Ok(xml),
        IdentifierEncryptionPolicy::EncryptIdentifiers => encrypt(&xml, setting, peer),
    }
}

pub(crate) fn decrypt_name_id(xml: &str, setting: &EntitySetting) -> Result<NameId, SamlError> {
    match decrypted(xml, EncryptedChild::EncryptedId, setting)? {
        (Identifier::Plain(name_id), _) => Ok(name_id),
        (Identifier::Encrypted, _) => Err(SamlError::ProtocolProfile(
            "EncryptedID must carry one NameID".into(),
        )),
    }
}

pub(crate) fn decrypt_new_id(xml: &str, setting: &EntitySetting) -> Result<String, SamlError> {
    match decrypted(xml, EncryptedChild::NewEncryptedId, setting)? {
        (_, Change::Plain(NameIdChange::NewId(value))) => Ok(value),
        (_, Change::Plain(NameIdChange::Terminate) | Change::Encrypted) => Err(
            SamlError::ProtocolProfile("NewEncryptedID must carry one NewID".into()),
        ),
    }
}

fn decrypted(
    xml: &str,
    child: EncryptedChild,
    setting: &EntitySetting,
) -> Result<(Identifier, Change), SamlError> {
    let request = decrypt(xml, child, setting)?;
    crate::schema::document(&request, setting.xml_limits, setting.schema_validator)?;
    identifier_and_change(&parse_saml_with_limits(&request, setting.xml_limits)?)
}

#[cfg(crypto)]
fn encrypt(xml: &str, setting: &EntitySetting, peer: &Metadata) -> Result<String, SamlError> {
    use crate::crypto::enc::{encrypt_root_children, EncryptionRecipient, MANAGED_NAME_ID, NEW_ID};

    encrypt_root_children(
        xml,
        &[MANAGED_NAME_ID, NEW_ID],
        &EncryptionRecipient::from_setting(peer.encryption_key_certificates(), setting),
    )
}

#[cfg(crypto)]
fn decrypt(xml: &str, child: EncryptedChild, setting: &EntitySetting) -> Result<String, SamlError> {
    use crate::crypto::enc::{decrypt_root_child, MANAGED_NAME_ID, NEW_ID};
    use crate::crypto::keys::load_decryption_keys;

    let key_pem = setting
        .enc_private_key
        .as_deref()
        .ok_or_else(|| SamlError::MissingKey("decryption_key".into()))?;
    let keys = load_decryption_keys(
        key_pem,
        setting.enc_private_key_pass.as_deref(),
        &setting.additional_decryption_keys,
    )?;
    let kind = match child {
        EncryptedChild::EncryptedId => MANAGED_NAME_ID,
        EncryptedChild::NewEncryptedId => NEW_ID,
    };
    decrypt_root_child(xml, kind, &keys, setting.into(), setting.xml_limits)
}

#[cfg(not(crypto))]
fn encrypt(_xml: &str, _setting: &EntitySetting, _peer: &Metadata) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML encryption requires a crypto provider feature".into(),
    ))
}

#[cfg(not(crypto))]
fn decrypt(
    _xml: &str,
    _child: EncryptedChild,
    _setting: &EntitySetting,
) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML decryption requires a crypto provider feature".into(),
    ))
}
