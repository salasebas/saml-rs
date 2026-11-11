//! `<EncryptedID>` in place of the `<NameID>` of a `<LogoutRequest>`.

use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::metadata::Metadata;

/// Whether a received `<LogoutRequest>` is authenticated. Only an
/// authenticated request has its `<EncryptedID>` decrypted.
#[derive(Debug, Clone, Copy)]
pub(super) enum LogoutRequestAuthentication {
    Authenticated,
    Unauthenticated,
}

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
                .get_x509_certificate(CertUse::Encryption)
                .ok_or_else(|| SamlError::MissingMetadata("encryption certificate".into()))?;
            encrypt(&xml, &certificate, init_setting)
        }
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn encrypt(xml: &str, certificate: &str, setting: &EntitySetting) -> Result<String, SamlError> {
    crate::crypto::enc::encrypt_logout_request_name_id(
        xml,
        certificate,
        &setting.data_encryption_algorithm,
        &setting.key_encryption_algorithm,
    )
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn encrypt(_xml: &str, _certificate: &str, _setting: &EntitySetting) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "XML encryption requires a crypto provider feature".into(),
    ))
}

/// `flow` with the `<EncryptedID>` of its `<LogoutRequest>` replaced by the
/// `<NameID>` it carries, decrypted with the local decryption key.
///
/// A request without an `<EncryptedID>`, an unauthenticated request, a
/// receiver without a decryption key, and an `<EncryptedID>` that no
/// decryption key decrypts return `flow` unchanged, so the `<EncryptedID>`
/// stays unread.
pub(super) fn decrypt_encrypted_id(
    flow: FlowResult,
    setting: &EntitySetting,
    authentication: LogoutRequestAuthentication,
) -> Result<FlowResult, SamlError> {
    let key_pem = match (authentication, setting.enc_private_key.as_deref()) {
        (LogoutRequestAuthentication::Authenticated, Some(key_pem)) => key_pem,
        (LogoutRequestAuthentication::Unauthenticated, _)
        | (LogoutRequestAuthentication::Authenticated, None) => return Ok(flow),
    };
    let document = crate::xml::dom::parse_with_limits(&flow.saml_content, setting.xml_limits)?;
    let carries_encrypted_id = document
        .root
        .children
        .iter()
        .any(|child| child.local_name == "EncryptedID");
    if !carries_encrypted_id {
        return Ok(flow);
    }
    let Some(saml_content) = decrypt(&flow.saml_content, key_pem, setting)? else {
        return Ok(flow);
    };
    crate::context::is_valid_xml_with_limits(&saml_content, setting.xml_limits)?;
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
    Ok(FlowResult {
        saml_content,
        extract,
        sig_alg: flow.sig_alg,
    })
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn decrypt(xml: &str, key_pem: &str, setting: &EntitySetting) -> Result<Option<String>, SamlError> {
    use crate::crypto::enc::{decrypt_logout_request_encrypted_id, AssertionDecryptionOptions};

    let keys = crate::crypto::keys::load_decryption_keys(
        key_pem,
        setting.enc_private_key_pass.as_deref(),
        &setting.additional_decryption_keys,
    )?;
    decrypt_logout_request_encrypted_id(
        xml,
        &keys,
        AssertionDecryptionOptions {
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
fn decrypt(
    _xml: &str,
    _key_pem: &str,
    _setting: &EntitySetting,
) -> Result<Option<String>, SamlError> {
    Err(SamlError::Unsupported(
        "XML decryption requires a crypto provider feature".into(),
    ))
}
