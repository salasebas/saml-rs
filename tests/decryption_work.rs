#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"))]

use std::ops::Range;

use bergshamra::xml::uppsala;
use saml_rs::constants::{
    data_encryption_algorithm::AES_256_GCM, key_encryption_algorithm::RSA_OAEP_MGF1P,
};
use saml_rs::crypto::enc::{decrypt_assertion, encrypt_assertion, AssertionDecryptionOptions};
use saml_rs::crypto::keys::{load_certificate, load_private_key};
use saml_rs::SamlError;

const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const OTHER_CERT: &str = include_str!("fixtures/key/idp/cert.cer");
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");
const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn element_range(
    xml: &str,
    namespace: &str,
    name: &str,
) -> Result<Range<usize>, Box<dyn std::error::Error>> {
    let document = uppsala::parse(xml)?;
    let element = document
        .descendants(document.root())
        .into_iter()
        .find(|node| {
            document
                .element(*node)
                .is_some_and(|element| element.matches_name_ns(namespace, name))
        })
        .ok_or("missing element")?;
    Ok(document.node_range(element).ok_or("missing source range")?)
}

fn encrypted_response(xml: &str) -> Result<String, SamlError> {
    encrypt_assertion(xml, CERT, AES_256_GCM, RSA_OAEP_MGF1P, "saml")
}

#[test]
fn encrypted_assertion_rejects_excess_key_candidates() -> TestResult {
    let encrypted = encrypted_response(RESPONSE)?;
    let other = encrypt_assertion(RESPONSE, OTHER_CERT, AES_256_GCM, RSA_OAEP_MGF1P, "saml")?;
    let candidate = &encrypted[element_range(&encrypted, ENC, "EncryptedKey")?];
    let wrong_key = &other[element_range(&other, ENC, "EncryptedKey")?];
    let key = load_private_key(KEY, None)?;
    for wrong_keys in [0, 30, 31] {
        let crowded = encrypted.replacen(
            candidate,
            &format!("{}{candidate}", wrong_key.repeat(wrong_keys)),
            1,
        );
        let result = decrypt_assertion(&crowded, &key, AssertionDecryptionOptions::default());
        if wrong_keys <= 30 {
            assert!(result?.1.contains("<saml:Assertion"));
        } else {
            assert!(
                matches!(result, Err(SamlError::Invalid(message)) if message.contains("ERR_DECRYPTION_LIMIT_EXCEEDED")),
                "excess candidates were not refused"
            );
        }
    }
    Ok(())
}

#[test]
fn encrypted_assertions_share_the_document_work_limit() -> TestResult {
    let encrypted = encrypted_response(RESPONSE)?;
    let assertion = &encrypted[element_range(&encrypted, SAML, "EncryptedAssertion")?];
    let key = load_private_key(KEY, None)?;
    for count in [16, 17] {
        let multiple = encrypted.replacen(assertion, &assertion.repeat(count), 1);
        let result = decrypt_assertion(&multiple, &key, AssertionDecryptionOptions::default());
        if count == 16 {
            let (plaintext, _) = result?;
            assert_eq!(plaintext.matches("<saml:Assertion ").count(), count);
        } else {
            assert!(
                matches!(result, Err(SamlError::Invalid(message)) if message.contains("ERR_DECRYPTION_LIMIT_EXCEEDED")),
                "aggregate work was not refused"
            );
        }
    }
    Ok(())
}

#[test]
fn revealed_encrypted_elements_share_the_outer_work_limit() -> TestResult {
    let encrypted = encrypted_response(RESPONSE)?;
    let data = &encrypted[element_range(&encrypted, ENC, "EncryptedData")?];
    let name_id = element_range(RESPONSE, SAML, "NameID")?;
    let key = load_private_key(KEY, None)?;
    let mut manager = bergshamra::KeysManager::new();
    manager.add_key(load_certificate(CERT)?);
    let plaintext_id = RESPONSE[name_id.clone()].replacen(
        "<saml:NameID ",
        &format!("<saml:NameID xmlns:saml=\"{SAML}\" "),
        1,
    );
    let encrypted_id = bergshamra::encrypt(
        &bergshamra::EncContext::new(manager),
        data,
        plaintext_id.as_bytes(),
    )?;
    for candidates in [29, 30] {
        let wrapped_key = &encrypted_id[element_range(&encrypted_id, ENC, "EncryptedKey")?];
        let inner = encrypted_id.replacen(wrapped_key, &wrapped_key.repeat(candidates), 1);
        let mut response = RESPONSE.to_owned();
        response.replace_range(
            name_id.clone(),
            &format!("<saml:EncryptedID>{inner}</saml:EncryptedID>"),
        );
        let outer = encrypted_response(&response)?;
        let result = decrypt_assertion(&outer, &key, AssertionDecryptionOptions::default());
        if candidates == 29 {
            assert!(result?.1.contains("EncryptedID"));
        } else {
            assert!(
                matches!(result, Err(SamlError::Invalid(message)) if message.contains("ERR_DECRYPTION_LIMIT_EXCEEDED")),
                "revealed work was not charged to the outer message"
            );
        }
    }
    Ok(())
}
