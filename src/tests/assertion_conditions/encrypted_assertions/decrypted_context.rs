use super::*;
use bergshamra::{encrypt, EncContext, KeysManager};
use saml_rs::constants::transform_algorithm::{C14N, ENVELOPED_SIGNATURE};
use saml_rs::crypto::keys::load_certificate;

const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

fn encrypt_assertion_as_written(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let end_tag = "</saml:Assertion>";
    let end = xml[start..].find(end_tag).ok_or("unterminated assertion")? + start + end_tag.len();
    let template = format!(
        r#"<xenc:EncryptedData xmlns:xenc="{ENC}" Type="{ENC}Element"><xenc:EncryptionMethod Algorithm="{AES_128_GCM}"/><ds:KeyInfo xmlns:ds="{DSIG}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{RSA_OAEP_MGF1P}"/><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
    );
    let mut keys = KeysManager::new();
    keys.add_key(load_certificate(CERT)?);
    let encrypted_data = encrypt(
        &EncContext::new(keys),
        &template,
        &xml.as_bytes()[start..end],
    )?;
    Ok(format!(
        "{}<saml:EncryptedAssertion>{encrypted_data}</saml:EncryptedAssertion>{}",
        &xml[..start],
        &xml[end..]
    ))
}

#[test]
fn a_decrypted_assertion_signature_verifies_with_the_namespaces_the_response_declares(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = post_exchange(require_signed())?;
    let unsigned = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let key = read_private_key(PRIVKEY, None)?;
    let inherited_prefix =
        drop_assertion_namespace_declaration(&sign_first_assertion(&unsigned, RSA_SHA256)?)?;
    let inclusive_transforms = [ENVELOPED_SIGNATURE.to_string(), C14N.to_string()];
    let inclusive_in_response = sign_saml_xml(
        &unsigned,
        false,
        &key,
        CERT,
        RSA_SHA256,
        &inclusive_transforms,
        None,
    )?;
    for signed_assertion in [inherited_prefix, inclusive_in_response] {
        let plaintext_response =
            sign_saml_xml(&signed_assertion, true, &key, CERT, RSA_SHA256, &[], None)?;
        accept(&exchange, &plaintext_response)?;

        let encrypted = encrypt_assertion_as_written(&signed_assertion)?;
        let session = accept(&exchange, &resign_response(&encrypted)?)?;
        assert_eq!(
            session.name_id().ok_or("missing NameID")?.value(),
            "alice@example.com"
        );
    }
    Ok(())
}

fn declarations(prefix: &str, count: usize) -> String {
    (0..count)
        .map(|index| format!(r#" xmlns:{prefix}{index}="urn:example:{prefix}:{index}""#))
        .collect()
}

fn crowded_encrypted_response(
    exchange: &Exchange,
    response_declarations: usize,
    assertion_declarations: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let crowded = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?
        .replacen(
            r#" Version="2.0""#,
            &format!(
                r#"{} Version="2.0""#,
                declarations("r", response_declarations)
            ),
            1,
        )
        .replacen(
            "<saml:Assertion ",
            &format!(
                "<saml:Assertion{} ",
                declarations("a", assertion_declarations)
            ),
            1,
        );
    resign_response(&encrypt_assertion_as_written(&crowded)?)
}

#[test]
fn an_unsigned_decrypted_assertion_is_reported_unsigned_at_the_attribute_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let allowing = post_exchange(SpValidationPolicy::default())?;
    accept(&allowing, &crowded_encrypted_response(&allowing, 30, 30)?)?;

    let requiring = post_exchange(require_signed())?;
    expect_error(
        accept(&requiring, &crowded_encrypted_response(&requiring, 30, 30)?),
        |error| matches!(error, SamlError::SignatureMissing),
    )
}
