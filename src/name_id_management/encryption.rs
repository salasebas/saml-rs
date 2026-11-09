//! `EncryptedID` and `NewEncryptedID` in a `ManageNameIDRequest`.

use crate::config::IdentifierEncryptionPolicy;
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::NameId;
use crate::xml::protocol_element::parse_saml_with_limits;

use super::{identifier_and_change, Change, Identifier, NameIdChange};

/// An encrypted child of a `ManageNameIDRequest`.
#[derive(Debug, Clone, Copy)]
enum EncryptedChild {
    /// `EncryptedID`, which carries a `NameID`.
    EncryptedId,
    /// `NewEncryptedID`, which carries a `NewID`.
    NewEncryptedId,
}

/// The rendered request, with its `NameID` and `NewID` replaced by
/// `EncryptedID` and `NewEncryptedID` for the peer's encryption certificate
/// when `policy` selects it.
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

/// The `NameID` that the request's `EncryptedID` carries.
pub(crate) fn decrypt_name_id(xml: &str, setting: &EntitySetting) -> Result<NameId, SamlError> {
    match decrypted(xml, EncryptedChild::EncryptedId, setting)? {
        (Identifier::Plain(name_id), _) => Ok(name_id),
        (Identifier::Encrypted, _) => Err(SamlError::ProtocolProfile(
            "EncryptedID must carry one NameID".into(),
        )),
    }
}

/// The new value that the request's `NewEncryptedID` carries.
pub(crate) fn decrypt_new_id(xml: &str, setting: &EntitySetting) -> Result<String, SamlError> {
    match decrypted(xml, EncryptedChild::NewEncryptedId, setting)? {
        (_, Change::Plain(NameIdChange::NewId(value))) => Ok(value),
        (_, Change::Plain(NameIdChange::Terminate) | Change::Encrypted) => Err(
            SamlError::ProtocolProfile("NewEncryptedID must carry one NewID".into()),
        ),
    }
}

/// The identifier and change of the request with `child` decrypted in place,
/// read again with the strict request reader.
fn decrypted(
    xml: &str,
    child: EncryptedChild,
    setting: &EntitySetting,
) -> Result<(Identifier, Change), SamlError> {
    let request = decrypt(xml, child, setting)?;
    identifier_and_change(&parse_saml_with_limits(&request, setting.xml_limits)?)
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn encrypt(xml: &str, setting: &EntitySetting, peer: &Metadata) -> Result<String, SamlError> {
    use crate::constants::CertUse;
    use crate::crypto::enc::{encrypt_root_children, MANAGED_NAME_ID, NEW_ID};

    let certificate = peer
        .get_x509_certificate(CertUse::Encryption)
        .ok_or_else(|| SamlError::MissingMetadata("encryption certificate".into()))?;
    encrypt_root_children(
        xml,
        &[MANAGED_NAME_ID, NEW_ID],
        &certificate,
        &setting.data_encryption_algorithm,
        &setting.key_encryption_algorithm,
    )
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn decrypt(xml: &str, child: EncryptedChild, setting: &EntitySetting) -> Result<String, SamlError> {
    use crate::crypto::enc::{
        decrypt_root_child, AssertionDecryptionOptions, MANAGED_NAME_ID, NEW_ID,
    };
    use crate::crypto::keys::load_private_key;

    let key_pem = setting
        .enc_private_key
        .as_deref()
        .ok_or_else(|| SamlError::MissingKey("decryption_key".into()))?;
    let key = load_private_key(key_pem, setting.enc_private_key_pass.as_deref())?;
    let kind = match child {
        EncryptedChild::EncryptedId => MANAGED_NAME_ID,
        EncryptedChild::NewEncryptedId => NEW_ID,
    };
    decrypt_root_child(
        xml,
        kind,
        &key,
        AssertionDecryptionOptions {
            allow_insecure_software_rsa_key_transport_decryption: setting
                .allow_insecure_software_rsa_key_transport_decryption,
            allow_rsa15_key_transport_decryption: setting.allow_rsa15_key_transport_decryption,
        },
        setting.xml_limits,
    )
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn encrypt(_xml: &str, _setting: &EntitySetting, _peer: &Metadata) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML encryption requires a crypto provider feature".into(),
    ))
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn decrypt(
    _xml: &str,
    _child: EncryptedChild,
    _setting: &EntitySetting,
) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML decryption requires a crypto provider feature".into(),
    ))
}
