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

fn encrypted_data(plaintext: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let template = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{ENC}\" Type=\"{ENC}Element\"><xenc:EncryptionMethod Algorithm=\"{AES_256_GCM}\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{RSA_OAEP_MGF1P}\"/><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>"
    );
    let mut manager = bergshamra::KeysManager::new();
    manager.add_key(load_certificate(CERT)?);
    Ok(bergshamra::encrypt(
        &bergshamra::EncContext::new(manager),
        &template,
        plaintext,
    )?)
}

#[test]
fn decrypted_assertion_can_inherit_namespace_prefixes() -> TestResult {
    let encrypted = encrypted_response(RESPONSE)?;
    let data_range = element_range(&encrypted, ENC, "EncryptedData")?;
    let assertion = &RESPONSE[element_range(RESPONSE, SAML, "Assertion")?];
    assert!(!assertion.contains("xmlns:saml="));
    let data = encrypted_data(assertion.as_bytes())?;
    let mut inherited = encrypted;
    inherited.replace_range(data_range, &data);
    let (response, plaintext) = decrypt_assertion(
        &inherited,
        &load_private_key(KEY, None)?,
        AssertionDecryptionOptions::default(),
    )?;
    assert!(response.contains(assertion));
    assert_eq!(plaintext, assertion);
    Ok(())
}

#[test]
fn encrypted_assertion_rejects_excess_key_candidates() -> TestResult {
    let encrypted = encrypted_response(RESPONSE)?;
    let other = encrypt_assertion(RESPONSE, OTHER_CERT, AES_256_GCM, RSA_OAEP_MGF1P, "saml")?;
    let candidate = &encrypted[element_range(&encrypted, ENC, "EncryptedKey")?];
    let wrong_key = &other[element_range(&other, ENC, "EncryptedKey")?];
    let key = load_private_key(KEY, None)?;
    assert_eq!(
        AssertionDecryptionOptions::default().max_decryption_work,
        16
    );
    for (maximum, wrong_keys, accepted) in [
        (16, 0, true),
        (16, 14, true),
        (16, 15, false),
        (32, 30, true),
        (32, 31, false),
        (1, 0, false),
        (0, 0, false),
    ] {
        let crowded = encrypted.replacen(
            candidate,
            &format!("{}{candidate}", wrong_key.repeat(wrong_keys)),
            1,
        );
        let mut options = AssertionDecryptionOptions::default();
        options.max_decryption_work = maximum;
        let result = decrypt_assertion(&crowded, &key, options);
        if accepted {
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
    for (maximum, count, accepted) in [
        (16, 8, true),
        (16, 9, false),
        (32, 16, true),
        (32, 17, false),
    ] {
        let multiple = encrypted.replacen(assertion, &assertion.repeat(count), 1);
        let mut options = AssertionDecryptionOptions::default();
        options.max_decryption_work = maximum;
        let result = decrypt_assertion(&multiple, &key, options);
        if accepted {
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
    let name_id = element_range(RESPONSE, SAML, "NameID")?;
    let key = load_private_key(KEY, None)?;
    let plaintext_id = RESPONSE[name_id.clone()].replacen(
        "<saml:NameID ",
        &format!("<saml:NameID xmlns:saml=\"{SAML}\" "),
        1,
    );
    let encrypted_id = encrypted_data(plaintext_id.as_bytes())?;
    for (maximum, candidates, accepted) in [
        (16, 13, true),
        (16, 14, false),
        (32, 29, true),
        (32, 30, false),
    ] {
        let wrapped_key = &encrypted_id[element_range(&encrypted_id, ENC, "EncryptedKey")?];
        let inner = encrypted_id.replacen(wrapped_key, &wrapped_key.repeat(candidates), 1);
        let mut response = RESPONSE.to_owned();
        response.replace_range(
            name_id.clone(),
            &format!("<saml:EncryptedID>{inner}</saml:EncryptedID>"),
        );
        let outer = encrypted_response(&response)?;
        let mut options = AssertionDecryptionOptions::default();
        options.max_decryption_work = maximum;
        let result = decrypt_assertion(&outer, &key, options);
        if accepted {
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
