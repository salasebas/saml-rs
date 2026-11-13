//! XML Signature Wrapping (XSW) attack-vector corpus. Each variant must never
//! surface attacker-controlled content as cryptographically trusted.
#![cfg(crypto)]
#![allow(clippy::unwrap_used)]

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::binding::base64_encode;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{construct_saml_signature, verify_signature};
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::util::normalize_cert_string;
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{constants::Binding, constants::ParserType, SamlError};

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");
const ATTACK: &str = include_str!("fixtures/misc/attack_response_signed.xml");

const FORGED: &str = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_forged\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion>";

/// Sign the assertion inside `response.xml` and return the signed Response.
fn signed_response() -> String {
    let key = load_private_key(PRIVKEY, None).unwrap();
    construct_saml_signature(RESPONSE, false, &key, CERT, RSA_SHA256, &[], None).unwrap()
}

fn response_signed_over_top_level_issuer() -> Result<String, Box<dyn std::error::Error>> {
    let issuer_id = "_signed_issuer";
    let with_issuer_id = RESPONSE.replacen(
        "<saml:Issuer>",
        &format!("<saml:Issuer ID=\"{issuer_id}\">"),
        1,
    );
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#{issuer_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(CERT),
    );
    let template = with_issuer_id.replacen(
        "</saml:Issuer><samlp:Status>",
        &format!("</saml:Issuer>{signature}<samlp:Status>"),
        1,
    );
    let key = load_private_key(PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

fn authn_request_signed_over_issuer() -> Result<String, Box<dyn std::error::Error>> {
    let issuer_id = "_signed_issuer";
    let xml = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_unsigned_authn_root\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" Destination=\"https://idp.example.com/sso\" AssertionConsumerServiceURL=\"https://evil.example.com/acs\"><saml:Issuer ID=\"{issuer_id}\">https://sp.example.com/metadata</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\"/></samlp:AuthnRequest>"
    );
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#{issuer_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(CERT),
    );
    let template = xml.replacen(
        "</saml:Issuer><samlp:NameIDPolicy",
        &format!("</saml:Issuer>{signature}<samlp:NameIDPolicy"),
        1,
    );
    let key = load_private_key(PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

/// The legitimately signed Response must verify and yield the real assertion.
#[test]
fn xsw_baseline_signed_response_verifies() -> Result<(), Box<dyn std::error::Error>> {
    let (verified, content) = verify_signature(&signed_response(), &[CERT.to_string()])?;
    assert!(verified);
    assert!(content.unwrap_or_default().contains("Assertion"));
    Ok(())
}

#[test]
fn xsw_authn_request_reference_must_cover_consumed_root() -> Result<(), Box<dyn std::error::Error>>
{
    let signed = authn_request_signed_over_issuer()?;
    match verify_signature(&signed, &[CERT.to_string()]) {
        Err(SamlError::SignedReferenceMismatch) => {
            // Expected rejection.
        }
        Ok((true, content)) => {
            return Err(format!(
                "issuer-only signature must not verify AuthnRequest root: {content:?}"
            )
            .into())
        }
        other => return Err(format!("unexpected verification result: {other:?}").into()),
    }

    let encoded = base64_encode(signed.as_bytes());
    let request = HttpRequest::post(vec![("SAMLRequest".into(), encoded)]);
    let certs = [CERT.to_string()];
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlRequest);
    options.check_signature = true;
    options.from_issuer = Some("https://sp.example.com/metadata");
    options.signing_certs = &certs;
    match flow(&options, &request) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        Ok(result) => Err(format!(
            "flow must not consume attacker AuthnRequest ACS: {:?}",
            result
                .extract
                .get_str("request.assertionConsumerServiceURL")
        )
        .into()),
        other => Err(format!("unexpected flow result: {other:?}").into()),
    }
}

#[test]
fn xsw_reference_must_cover_returned_assertion() -> Result<(), Box<dyn std::error::Error>> {
    let signed = response_signed_over_top_level_issuer()?;
    match verify_signature(&signed, &[CERT.to_string()]) {
        Err(SamlError::PotentialWrappingAttack) => Ok(()),
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        Ok((true, content)) => Err(format!(
            "issuer-only signature must not verify assertion content: {content:?}"
        )
        .into()),
        other => Err(format!("unexpected verification result: {other:?}").into()),
    }
}

/// A forged top-level element before the signed response is rejected as a
/// malformed XML document before signature verification.
#[test]
fn xsw_multi_root_wrapping_rejected_before_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    match verify_signature(ATTACK, &[CERT.to_string()]) {
        Err(SamlError::Xml(message)) if message == "multiple document elements" => Ok(()),
        Ok(result) => Err(format!("multi-root wrapper must not verify: {result:?}").into()),
        Err(other) => Err(format!("unexpected error: {other:?}").into()),
    }
}

/// A forged sibling assertion prepended before the signed one is never trusted.
#[test]
fn xsw_sibling_forged_assertion_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let pos = signed.find("<saml:Assertion").ok_or("no assertion")?;
    let wrapped = format!("{}{}{}", &signed[..pos], FORGED, &signed[pos..]);
    match verify_signature(&wrapped, &[CERT.to_string()]) {
        Err(SamlError::PotentialWrappingAttack) => Ok(()),
        Ok((false, _)) => Ok(()),
        Ok((true, content)) => {
            assert!(!content.unwrap_or_default().contains("attacker@evil.com"));
            Ok(())
        }
        Err(other) => Err(format!("unexpected error: {other:?}").into()),
    }
}

#[test]
fn xsw_duplicate_id_wrapping_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let duplicate = FORGED.replace(
        "ID=\"_forged\"",
        "ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"",
    );
    let pos = signed.find("<saml:Assertion").ok_or("no assertion")?;
    let wrapped = format!("{}{}{}", &signed[..pos], duplicate, &signed[pos..]);

    match verify_signature(&wrapped, &[CERT.to_string()]) {
        Err(SamlError::PotentialWrappingAttack) => Ok(()),
        Ok((false, _)) => Ok(()),
        Ok((true, content)) => {
            Err(format!("duplicate-ID wrapper must not verify: {:?}", content).into())
        }
        Err(other) => Err(format!("unexpected error: {other:?}").into()),
    }
}

/// A forged sibling assertion appended after the signed one is never trusted.
#[test]
fn xsw_trailing_forged_assertion_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let pos = signed
        .rfind("</samlp:Response>")
        .ok_or("no response close")?;
    let wrapped = format!("{}{}{}", &signed[..pos], FORGED, &signed[pos..]);
    match verify_signature(&wrapped, &[CERT.to_string()]) {
        Err(SamlError::PotentialWrappingAttack) => Ok(()),
        Ok((false, _)) => Ok(()),
        Ok((true, content)) => {
            assert!(!content.unwrap_or_default().contains("attacker@evil.com"));
            Ok(())
        }
        Err(other) => Err(format!("unexpected error: {other:?}").into()),
    }
}

/// Tampering with signed content invalidates the signature.
#[test]
fn xsw_tampered_signed_content_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let tampered = signed.replacen(
        "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
        "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d8",
        1,
    );
    assert!(!verify_signature(&tampered, &[CERT.to_string()])?.0);
    Ok(())
}

/// An XML comment inside a value must not truncate it (comment-splice resistance).
#[test]
fn xsw_comment_splice_reads_full_value() -> Result<(), Box<dyn std::error::Error>> {
    let xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Subject><saml:NameID>user<!---->@victim.com</saml:NameID></saml:Subject></saml:Assertion>";
    let r = extract(
        xml,
        &[ExtractorField::new(
            "nameID",
            &["Assertion", "Subject", "NameID"],
        )],
    )?;
    assert_eq!(r.get_str("nameID"), Some("user@victim.com"));
    Ok(())
}

/// An unsigned response is never trusted.
#[test]
fn xsw_unsigned_response_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let (verified, content) = verify_signature(RESPONSE, &[CERT.to_string()])?;
    assert!(!verified);
    assert!(content.is_none());
    Ok(())
}
