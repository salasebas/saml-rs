use super::*;
use crate::config::DecryptionCredential;
use crate::constants::{
    data_encryption_algorithm::AES_256_GCM, key_encryption_algorithm::RSA_OAEP_MGF1P,
};
use crate::crypto::keys::load_private_key;
use crate::xml::XmlLimits;

const KEY: &str = include_str!("../../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn unsigned_requested_subject_uses_the_canonicalized_data_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let data = encrypt::encrypted_data_xml(
        b"<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">alice</saml:NameID>",
        CERT,
        crate::constants::data_encryption_algorithm::AES_256,
        RSA_OAEP_MGF1P.into(),
    )?;
    let shadowed = data.replacen(
        "<xenc:EncryptionMethod ",
        "<xenc:EncryptionMethod xmlns:other=\"urn:attributes\" other:Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\" ",
        1,
    );
    let request = format!("<samlp:AuthnRequest xmlns:samlp=\"{}\" xmlns:saml=\"{}\"><saml:Subject><saml:EncryptedID>{shadowed}</saml:EncryptedID></saml:Subject></samlp:AuthnRequest>", namespace::PROTOCOL, namespace::ASSERTION);
    assert!(decrypt_authn_request_encrypted_id(
        &request,
        KEY,
        None,
        &[],
        AssertionDecryptionOptions::default(),
        XmlLimits::default(),
        RequestAuthentication::Unauthenticated,
    )?
    .is_none());
    assert!(decrypt_authn_request_encrypted_id(
        &request,
        KEY,
        None,
        &[],
        AssertionDecryptionOptions::default(),
        XmlLimits::default(),
        RequestAuthentication::Authenticated,
    )?
    .is_some());
    Ok(())
}

#[test]
fn other_inbound_encrypted_elements_preflight_the_document(
) -> Result<(), Box<dyn std::error::Error>> {
    let data = encrypt::encrypted_data_xml(
        b"<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">alice</saml:NameID>",
        CERT,
        AES_256_GCM,
        RSA_OAEP_MGF1P.into(),
    )?;
    let document = parse_xml_document(&data)?;
    let key_info = document
        .descendants(document.root())
        .into_iter()
        .find(|node| {
            document
                .element(*node)
                .is_some_and(|element| element.matches_name_ns(ENC, "EncryptedKey"))
        })
        .ok_or("missing key")?;
    let key_xml = &data[node_range(&document, key_info)?];
    let crowded = data.replacen(key_xml, &key_xml.repeat(32), 1);
    let keys = [load_private_key(KEY, None)?];
    let limits = XmlLimits::default();
    let wrap = |root: &str, body: &str| {
        format!(
            "<{root} xmlns:saml=\"{}\" xmlns:samlp=\"{}\">{body}</{root}>",
            namespace::ASSERTION,
            namespace::PROTOCOL
        )
    };
    let encrypted_id = format!("<saml:EncryptedID>{crowded}</saml:EncryptedID>");
    let request = wrap(
        "samlp:AuthnRequest",
        &format!("<saml:Subject>{encrypted_id}</saml:Subject>"),
    );
    let logout = wrap("samlp:LogoutRequest", &encrypted_id);
    let manage = wrap(
        "samlp:ManageNameIDRequest",
        &format!("{encrypted_id}<samlp:NewEncryptedID>{crowded}</samlp:NewEncryptedID>"),
    );
    let assertion = wrap(
        "saml:Assertion",
        &format!("<saml:Subject>{encrypted_id}</saml:Subject>"),
    );
    let attribute = wrap("saml:Assertion", &format!("<saml:AttributeStatement><saml:EncryptedAttribute>{crowded}</saml:EncryptedAttribute></saml:AttributeStatement>"));
    for (maximum, exceeds) in [(16, true), (1, true), (128, false)] {
        let options = AssertionDecryptionOptions {
            max_decryption_work: maximum,
            ..AssertionDecryptionOptions::default()
        };
        for result in [
            decrypt_authn_request_encrypted_id(
                &request,
                KEY,
                None,
                &[] as &[DecryptionCredential],
                options,
                limits,
                RequestAuthentication::Unauthenticated,
            )
            .map(|_| ()),
            decrypt_logout_request_encrypted_id(&logout, &keys, options, limits).map(|_| ()),
            decrypt_root_child(&manage, MANAGED_NAME_ID, &keys, options, limits).map(|_| ()),
            decrypt_root_child(&manage, NEW_ID, &keys, options, limits).map(|_| ()),
            decrypt_assertion_elements(
                &assertion,
                &keys,
                options,
                limits,
                AssertionElementEncryption::default(),
                crate::config::ReceivedEncryptedElements::DecryptReceived,
            )
            .map(|_| ()),
            decrypt_assertion_elements(
                &attribute,
                &keys,
                options,
                limits,
                AssertionElementEncryption::default(),
                crate::config::ReceivedEncryptedElements::DecryptReceived,
            )
            .map(|_| ()),
        ] {
            assert_eq!(
                matches!(result, Err(SamlError::Invalid(message)) if message.contains("ERR_DECRYPTION_LIMIT_EXCEEDED")),
                exceeds,
                "inbound entry point did not honor the configured work allowance"
            );
        }
    }
    Ok(())
}
