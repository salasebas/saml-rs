use super::*;
use crate::constants::signature_algorithm::{RSA_SHA256, RSA_SHA384, RSA_SHA512};
use crate::constants::{digest_for_signature, namespace, transform_algorithm};
use crate::crypto::construct_saml_signature;
use crate::crypto::keys::load_private_key;
use crate::util::normalize_cert_string;
use crate::xml::{extract, ExtractorField};
use bergshamra::sign;

#[test]
fn external_reference_detection() {
    assert!(!is_external_reference("")); // whole document
    assert!(!is_external_reference("#_assertion123")); // same-document
    assert!(is_external_reference("https://evil.example.com/x"));
    assert!(is_external_reference("/etc/passwd"));
    assert!(is_external_reference("file:///etc/passwd"));
    assert!(is_external_reference("cid:attachment"));
}

#[test]
fn metadata_signature_transform_allowlist_preserves_canonicalization_interoperability() {
    const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    const XSLT_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
    const UNKNOWN_TRANSFORM: &str = "urn:example:unknown-transform";

    for algorithm in [
        transform_algorithm::ENVELOPED_SIGNATURE,
        transform_algorithm::EXC_C14N,
        transform_algorithm::EXC_C14N_WITH_COMMENTS,
        XML_C14N_10,
        XML_C14N_10_WITH_COMMENTS,
        XML_C14N_11,
        XML_C14N_11_WITH_COMMENTS,
    ] {
        assert!(
            metadata_signature_transform_allowed(algorithm),
            "{algorithm}"
        );
    }

    for algorithm in [XPATH_TRANSFORM, XSLT_TRANSFORM, UNKNOWN_TRANSFORM] {
        assert!(
            !metadata_signature_transform_allowed(algorithm),
            "{algorithm}"
        );
    }
}

#[test]
fn same_document_reference_target_parsing() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(verified_target_from_uri("")?, VerifiedTarget::WholeDocument);
    assert_eq!(
        verified_target_from_uri("#_assertion123")?,
        VerifiedTarget::Id("_assertion123".to_string())
    );
    assert_eq!(
        verified_target_from_uri("#xpointer(/)")?,
        VerifiedTarget::WholeDocument
    );
    assert_eq!(
        verified_target_from_uri("#xpointer(id('_assertion123'))")?,
        VerifiedTarget::Id("_assertion123".to_string())
    );
    Ok(())
}

#[test]
fn unsupported_reference_target_parsing_fails() {
    assert!(matches!(
        verified_target_from_uri("#"),
        Err(SamlError::ReferenceResolution {
            reason: ReferenceResolutionReason::UnsupportedReferenceUri
        })
    ));
    assert!(matches!(
        verified_target_from_uri("#xpointer(//saml:Assertion)"),
        Err(SamlError::ReferenceResolution {
            reason: ReferenceResolutionReason::UnsupportedReferenceUri
        })
    ));
}

fn preflight_signature(
    canonicalization: &str,
    signature: &str,
    digest: &str,
    transform: &str,
    references: usize,
    uri: &str,
) -> Result<(), SamlError> {
    let reference = format!(
        "<ds:Reference URI=\"{uri}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{transform}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>",
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
    );
    let xml = format!(
        "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:ds=\"{dsig}\" ID=\"_response\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{canonicalization}\"/><ds:SignatureMethod Algorithm=\"{signature}\"/>{references}</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></samlp:Response>",
        protocol = namespace::PROTOCOL,
        dsig = namespace::DSIG,
        references = reference.repeat(references),
    );
    let document = uppsala::parse(&xml).map_err(|error| SamlError::Crypto(error.to_string()))?;
    let root = document
        .document_element()
        .ok_or_else(|| SamlError::Crypto("profile fixture is missing a document element".into()))?;
    let signature = document
        .first_child_element_by_name_ns(root, bergshamra_ns::DSIG, bergshamra_ns::node::SIGNATURE)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    enforce_strict_profile_on_verified_signature(&document, signature)
}

#[test]
fn strict_saml_signature_preflight_accepts_only_the_initial_profile() {
    for (signature, digest) in [
        (RSA_SHA256, crate::constants::digest_algorithm::SHA256),
        (RSA_SHA384, crate::constants::digest_algorithm::SHA384),
        (RSA_SHA512, crate::constants::digest_algorithm::SHA512),
    ] {
        assert!(preflight_signature(
            transform_algorithm::EXC_C14N,
            signature,
            digest,
            transform_algorithm::EXC_C14N,
            1,
            "#_response",
        )
        .is_ok());
    }
}

#[test]
fn strict_saml_signature_preflight_rejects_ambiguous_references_and_algorithms() {
    let accepted = (
        transform_algorithm::EXC_C14N,
        RSA_SHA256,
        crate::constants::digest_algorithm::SHA256,
        transform_algorithm::EXC_C14N,
    );
    for (references, uri) in [(0, "#_response"), (2, "#_response"), (1, "")] {
        assert!(preflight_signature(
            accepted.0, accepted.1, accepted.2, accepted.3, references, uri,
        )
        .is_err());
    }
    for rejected in [
        preflight_signature(
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            accepted.1,
            accepted.2,
            accepted.3,
            1,
            "#_response",
        ),
        preflight_signature(
            accepted.0,
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            accepted.2,
            accepted.3,
            1,
            "#_response",
        ),
        preflight_signature(
            accepted.0,
            accepted.1,
            "http://www.w3.org/2000/09/xmldsig#sha1",
            accepted.3,
            1,
            "#_response",
        ),
        preflight_signature(
            accepted.0,
            accepted.1,
            accepted.2,
            "http://www.w3.org/TR/1999/REC-xslt-19991116",
            1,
            "#_response",
        ),
    ] {
        assert!(matches!(rejected, Err(SamlError::AlgorithmUnsupported)));
    }
}

#[test]
fn advice_assertion_is_not_a_wrapping_shape() -> Result<(), Box<dyn std::error::Error>> {
    let document = dom::parse(&format!(
        "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\"><saml:Assertion ID=\"_outer\"><saml:Advice><saml:Assertion ID=\"_advice\"/></saml:Advice></saml:Assertion></samlp:Response>",
        protocol = namespace::PROTOCOL,
        assertion = namespace::ASSERTION,
    ))?;
    assert!(!wrapping_detected(&document.root));
    Ok(())
}

#[test]
fn subject_confirmation_data_assertion_is_a_wrapping_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let document = dom::parse(&format!(
        "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\"><saml:Assertion ID=\"_outer\"><saml:Subject><saml:SubjectConfirmation><saml:SubjectConfirmationData><saml:Assertion ID=\"_nested\"/></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>",
        protocol = namespace::PROTOCOL,
        assertion = namespace::ASSERTION,
    ))?;
    assert!(wrapping_detected(&document.root));
    Ok(())
}

#[test]
fn duplicate_saml_id_allows_unique_ids() -> Result<(), Box<dyn std::error::Error>> {
    let doc = dom::parse(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/></samlp:Response>"#,
    )?;
    let mut seen = HashSet::new();
    assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
    Ok(())
}

#[test]
fn duplicate_saml_id_returns_repeated_value() -> Result<(), Box<dyn std::error::Error>> {
    let doc = dom::parse(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/></samlp:Response>"#,
    )?;
    let mut seen = HashSet::new();
    assert_eq!(
        duplicate_saml_id(&doc.root, &mut seen),
        Some("_same".to_string())
    );
    Ok(())
}

#[test]
fn duplicate_saml_id_ignores_empty_values() -> Result<(), Box<dyn std::error::Error>> {
    let doc = dom::parse(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID=""><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID=""/></samlp:Response>"#,
    )?;
    let mut seen = HashSet::new();
    assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
    Ok(())
}

const RESPONSE_SIGNED: &str = include_str!("../../../tests/fixtures/misc/response_signed.xml");
const SIGNED_REQUEST: &str = include_str!("../../../tests/fixtures/misc/signed_request_sha256.xml");
const ATTACK: &str = include_str!("../../../tests/fixtures/misc/attack_response_signed.xml");
const FALSE_SIGNED: &str =
    include_str!("../../../tests/fixtures/misc/false_signed_request_sha256.xml");
const RESPONSE: &str = include_str!("../../../tests/fixtures/misc/response.xml");
const SP_PRIVKEY: &str =
    include_str!("../../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
// IdP signing cert (matches the response_signed.xml signer / idpmeta).
const IDP_CERT: &str = include_str!("../../../tests/fixtures/key/idp/cert.cer");
// SP signing cert (matches signed_request_sha256.xml signer).
const SP_CERT: &str = include_str!("../../../tests/fixtures/key/sp/cert.cer");
const SP_SIGNING_CERT: &str =
    include_str!("../../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const UNTRUSTED_PRIVKEY: &str =
    include_str!("../../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const UNTRUSTED_CERT: &str = include_str!("../../../tests/fixtures/key/idp/cert.cer");

fn signed_response_with_foreign_extension_certificate() -> Result<String, Box<dyn std::error::Error>>
{
    let response = RESPONSE.replacen(
        "<samlp:Status>",
        r#"<samlp:Extensions><x:Signature xmlns:x="urn:example:extension"><x:X509Certificate>attacker</x:X509Certificate></x:Signature></samlp:Extensions><samlp:Status>"#,
        1,
    );
    let key = load_private_key(SP_PRIVKEY, None)?;
    Ok(construct_saml_signature(
        &response,
        false,
        &key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn response_with_first_invalid_signature() -> Result<String, Box<dyn std::error::Error>> {
    let cert = normalize_cert_string(IDP_CERT);
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let invalid_signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><ds:Transforms><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>invalid</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
    );
    Ok(RESPONSE_SIGNED.replacen(
        "<samlp:Status>",
        &format!("{invalid_signature}<samlp:Status>"),
        1,
    ))
}

fn signature_over_top_level_issuer(
    key_pem: &str,
    certificate: &str,
    algorithm: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let issuer_id = "_signed_response_issuer";
    let response = RESPONSE.replacen(
        "<saml:Issuer>",
        &format!("<saml:Issuer ID=\"{issuer_id}\">"),
        1,
    );
    let digest = digest_for_signature(algorithm).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#{issuer_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(certificate),
    );
    let template = response.replacen(
        "</saml:Issuer><samlp:Status>",
        &format!("</saml:Issuer>{signature}<samlp:Status>"),
        1,
    );
    let key = load_private_key(key_pem, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let context = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&context, &template)?)
}

fn signature_over_response_and_assertion() -> Result<String, Box<dyn std::error::Error>> {
    let document = dom::parse(RESPONSE)?;
    let response_id = node_saml_id(&document.root).ok_or("missing Response ID")?;
    let assertion = children_named(&document.root, "Assertion")
        .into_iter()
        .next()
        .ok_or("missing Assertion")?;
    let assertion_id = node_saml_id(assertion).ok_or("missing Assertion ID")?;
    let digest = digest_for_signature(RSA_SHA512).ok_or("unknown digest")?;
    let reference = |id: &str| {
        format!(
            "<ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference>",
            enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
            exc_c14n = transform_algorithm::EXC_C14N,
        )
    };
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/>{response_reference}{assertion_reference}</ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        algorithm = RSA_SHA512,
        response_reference = reference(response_id),
        assertion_reference = reference(assertion_id),
        cert = normalize_cert_string(SP_SIGNING_CERT),
    );
    let template = RESPONSE.replacen(
        "</saml:Issuer><samlp:Status>",
        &format!("</saml:Issuer>{signature}<samlp:Status>"),
        1,
    );
    let key = load_private_key(SP_PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let context = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&context, &template)?)
}

fn root_signature(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = dom::parse(xml)?;
    let signature = children_named(&document.root, "Signature")
        .into_iter()
        .next()
        .ok_or("missing root Signature")?;
    Ok(xml[signature.start..signature.end].to_string())
}

fn remove_signature_key_info(signature: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = dom::parse(signature)?;
    let key_info = children_named(&document.root, "KeyInfo")
        .into_iter()
        .next()
        .ok_or("missing KeyInfo")?;
    Ok(format!(
        "{}{}",
        &signature[..key_info.start],
        &signature[key_info.end..]
    ))
}

fn assertion_signed_response_with_extra_signature(
    extra_signature: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = RESPONSE.replacen(
        "<saml:Issuer>",
        "<saml:Issuer ID=\"_signed_response_issuer\">",
        1,
    );
    let key = load_private_key(SP_PRIVKEY, None)?;
    let assertion_signed = construct_saml_signature(
        &response,
        false,
        &key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    Ok(assertion_signed.replacen(
        "</samlp:Response>",
        &format!("{extra_signature}</samlp:Response>"),
        1,
    ))
}

fn sign_template(template: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = load_private_key(SP_PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let context = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&context, template)?)
}

fn response_signed_over_assertion_with_foreign_xpath() -> Result<String, Box<dyn std::error::Error>>
{
    const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    let document = dom::parse(RESPONSE)?;
    let assertion = children_named(&document.root, "Assertion")
        .into_iter()
        .next()
        .ok_or("missing Assertion")?;
    let assertion_id = node_saml_id(assertion).ok_or("missing Assertion ID")?;
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#{assertion_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><Transform xmlns=\"urn:example:other\" Algorithm=\"{xpath}\"><XPath>0</XPath></Transform><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc = transform_algorithm::EXC_C14N,
        algorithm = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        xpath = XPATH_TRANSFORM,
        digest = digest,
        cert = normalize_cert_string(SP_SIGNING_CERT),
    );
    let template = RESPONSE.replacen(
        "</saml:Issuer><samlp:Status>",
        &format!("</saml:Issuer>{signature}<samlp:Status>"),
        1,
    );
    sign_template(&template)
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
fn response_signed_over_assertion_with(
    algorithm: &str,
    digest: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let document = dom::parse(RESPONSE)?;
    let assertion = children_named(&document.root, "Assertion")
        .into_iter()
        .next()
        .ok_or("missing Assertion")?;
    let assertion_id = node_saml_id(assertion).ok_or("missing Assertion ID")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#{assertion_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc = transform_algorithm::EXC_C14N,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(SP_SIGNING_CERT),
    );
    let template = RESPONSE.replacen(
        "</saml:Issuer><samlp:Status>",
        &format!("</saml:Issuer>{signature}<samlp:Status>"),
        1,
    );
    sign_template(&template)
}

fn response_with_issuer_only_signature(
    canonicalization: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = RESPONSE.replacen(
        "<saml:Issuer>",
        "<saml:Issuer ID=\"_signed_response_issuer\">",
        1,
    );
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{canonicalization}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#_signed_response_issuer\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        algorithm = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        exc = transform_algorithm::EXC_C14N,
        digest = digest,
        cert = normalize_cert_string(SP_SIGNING_CERT),
    );
    let template = response.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
    sign_template(&template)
}

fn cid_reference_response() -> Result<String, Box<dyn std::error::Error>> {
    let cert = normalize_cert_string(SP_SIGNING_CERT);
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"cid:attachment-1@example.com\"><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?,
    );
    let template = RESPONSE.replacen("<samlp:Status>", &format!("{signature}<samlp:Status>"), 1);
    let key = load_private_key(SP_PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

fn assert_reference_resolution(
    result: Result<(bool, Option<String>), SamlError>,
    expected: ReferenceResolutionReason,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::ReferenceResolution { reason }) if reason == expected => Ok(()),
        other => Err(format!("expected reference resolution {expected}, got {other:?}").into()),
    }
}

#[test]
fn dsig_context_secure_defaults_survive_insecure_builder() {
    let ctx = DsigContext::new(KeysManager::new());
    assert!(ctx.trusted_keys_only);
    assert!(ctx.strict_verification);
    assert!(ctx.require_reference_digests);
    assert_eq!(ctx.hmac_min_out_len, 160);
    assert!(!ctx.insecure);

    let insecure = ctx.with_insecure(true);
    assert!(insecure.insecure);
    assert!(insecure.trusted_keys_only);
    assert!(insecure.strict_verification);
    assert!(insecure.require_reference_digests);
    assert_eq!(insecure.hmac_min_out_len, 160);
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn verifies_signed_response_with_metadata_cert() -> Result<(), Box<dyn std::error::Error>> {
    let (verified, content) = verify_signature(RESPONSE_SIGNED, &[IDP_CERT.to_string()])?;
    assert!(
        verified,
        "response_signed.xml should verify with the IdP cert"
    );
    assert!(content
        .ok_or("expected signed assertion")?
        .contains("Assertion"));
    Ok(())
}

#[test]
fn verifies_generated_same_document_signature() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(SP_PRIVKEY, None)?;
    let signed = construct_saml_signature(
        RESPONSE,
        false,
        &key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
    assert!(verified);
    assert!(content
        .ok_or("expected signed assertion")?
        .contains("Assertion"));
    Ok(())
}

#[test]
fn foreign_extension_certificate_is_not_treated_as_signature_key_info(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response_with_foreign_extension_certificate()?;
    let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
    assert!(verified);
    assert!(content
        .ok_or("expected signed assertion")?
        .contains("Assertion"));
    Ok(())
}

#[test]
fn detailed_verification_ignores_foreign_extension_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response_with_foreign_extension_certificate()?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(result.verified() && result.assertion_directly_covered());
    Ok(())
}

#[test]
fn inline_certificate_is_not_used_without_metadata_pin() -> Result<(), Box<dyn std::error::Error>> {
    match verify_signature(RESPONSE_SIGNED, &[]) {
        Err(SamlError::NoTrustedCertificate) => Ok(()),
        other => Err(format!("expected missing pinned certificate, got {other:?}").into()),
    }
}

#[test]
fn first_invalid_signature_prevents_later_valid_signature_from_authorizing_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = verify_signature(
        &response_with_first_invalid_signature()?,
        &[IDP_CERT.to_string()],
    )?;
    assert_eq!(result, (false, None));
    Ok(())
}

#[test]
fn detailed_verification_rejects_invalid_first_signature_before_later_assertion_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = verify_signatures_detailed_with_profile(
        &response_with_first_invalid_signature()?,
        &[IDP_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(!result.verified() && !result.response_covered());
    assert!(result.verified_embedded_signatures().is_empty());
    Ok(())
}

#[test]
fn detailed_verification_excludes_untrusted_extra_signature_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let untrusted = root_signature(&signature_over_top_level_issuer(
        UNTRUSTED_PRIVKEY,
        UNTRUSTED_CERT,
        RSA_SHA512,
    )?)?;
    let untrusted = remove_signature_key_info(&untrusted)?;
    let signed = assertion_signed_response_with_extra_signature(&untrusted)?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;

    let [signature] = result.verified_embedded_signatures() else {
        return Err("expected only the trusted Assertion signature".into());
    };
    assert!(result.verified() && result.assertion_directly_covered());
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert!(signature.assertion_directly_covered() && !signature.response_covered());
    Ok(())
}

#[test]
fn detailed_verification_excludes_valid_unrelated_signature_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let unrelated = root_signature(&signature_over_top_level_issuer(
        SP_PRIVKEY,
        SP_SIGNING_CERT,
        RSA_SHA512,
    )?)?;
    let signed = assertion_signed_response_with_extra_signature(&unrelated)?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;

    let [signature] = result.verified_embedded_signatures() else {
        return Err("expected only the Assertion-covering signature".into());
    };
    assert!(result.verified() && result.assertion_directly_covered());
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert!(signature.assertion_directly_covered() && !signature.response_covered());
    Ok(())
}

#[test]
fn extra_response_signature_that_does_not_verify_is_ignored_only_by_the_compatibility_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let extra = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#_response\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>",
        dsig = namespace::DSIG,
    );
    let signed = assertion_signed_response_with_extra_signature(&extra)?;
    let verify_under = |profile| {
        verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            None,
            XmlLimits::default(),
            profile,
        )
    };

    let compatible = verify_under(XmlSignatureProfile::AllowProviderSupportedForCompatibility)?;
    let [signature] = compatible.verified_embedded_signatures() else {
        return Err("expected only the trusted Assertion signature".into());
    };
    assert!(compatible.verified() && compatible.assertion_directly_covered());
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert!(signature.assertion_directly_covered() && !signature.response_covered());

    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        assert!(matches!(
            verify_under(profile),
            Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::XmlSignature
            })
        ));
    }
    Ok(())
}

#[test]
fn strict_profile_rejects_verified_covering_signature_with_two_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = signature_over_response_and_assertion()?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::StrictRsaSha2,
    );

    assert!(matches!(result, Err(SamlError::SignedReferenceMismatch)));
    Ok(())
}

#[test]
fn strict_profile_rejects_foreign_xpath_transform_on_verified_assertion_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = response_signed_over_assertion_with_foreign_xpath()?;
    let compatible = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    let [signature] = compatible.verified_embedded_signatures() else {
        return Err("expected the assertion-covering signature".into());
    };
    assert!(compatible.verified() && compatible.assertion_directly_covered());
    assert!(signature.assertion_directly_covered());

    let strict = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::StrictRsaSha2,
    );
    assert!(matches!(strict, Err(SamlError::AlgorithmUnsupported)));
    Ok(())
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn excluding_weak_algorithms_rejects_md5_and_ripemd160_but_keeps_sha1(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::constants::digest_algorithm::{SHA1, SHA256};
    use crate::constants::signature_algorithm::RSA_SHA1;
    const RSA_MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
    const RSA_RIPEMD160: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
    const MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";
    const RIPEMD160: &str = "http://www.w3.org/2001/04/xmlenc#ripemd160";

    let verify_under = |signed: &str, profile| {
        verify_signatures_detailed_with_profile(
            signed,
            &[SP_SIGNING_CERT.to_string()],
            None,
            XmlLimits::default(),
            profile,
        )
    };
    for (algorithm, digest, excluded) in [
        (RSA_MD5, SHA256, true),
        (RSA_RIPEMD160, SHA256, true),
        (RSA_SHA256, MD5, true),
        (RSA_SHA256, RIPEMD160, true),
        (RSA_SHA1, SHA1, false),
    ] {
        let signed = response_signed_over_assertion_with(algorithm, digest)?;
        let compatible = verify_under(
            &signed,
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?;
        assert!(compatible.verified() && compatible.assertion_directly_covered());

        let weak_excluded = verify_under(&signed, XmlSignatureProfile::ExcludeWeakAlgorithms);
        if excluded {
            assert!(
                matches!(weak_excluded, Err(SamlError::AlgorithmUnsupported)),
                "{algorithm} with {digest}: {weak_excluded:?}"
            );
        } else {
            assert!(weak_excluded?.verified(), "{algorithm} with {digest}");
        }
    }
    Ok(())
}

#[test]
fn strict_profile_ignores_verified_signature_that_does_not_authenticate_the_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = response_with_issuer_only_signature(XML_C14N_10)?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::StrictRsaSha2,
    );
    assert!(matches!(result, Err(SamlError::SignedReferenceMismatch)));
    Ok(())
}

#[test]
fn detailed_verification_reports_one_signature_covering_response_and_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = signature_over_response_and_assertion()?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;

    let [signature] = result.verified_embedded_signatures() else {
        return Err("expected one verified embedded signature".into());
    };
    assert!(result.verified() && result.assertion_directly_covered());
    assert!(result.response_covered());
    assert_eq!(signature.algorithm_uri(), RSA_SHA512);
    assert!(signature.assertion_directly_covered() && signature.response_covered());
    Ok(())
}

#[test]
fn detailed_verification_aggregates_rolling_cert_coverage_after_first_signature_verifies(
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion_key = load_private_key(UNTRUSTED_PRIVKEY, None)?;
    let signed_assertion = construct_saml_signature(
        RESPONSE,
        false,
        &assertion_key,
        IDP_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let response_key = load_private_key(SP_PRIVKEY, None)?;
    let signed_response_and_assertion = construct_saml_signature(
        &signed_assertion,
        true,
        &response_key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let result = verify_signatures_detailed_with_profile(
        &signed_response_and_assertion,
        &[SP_SIGNING_CERT.to_string(), IDP_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(result.verified() && result.assertion_directly_covered() && result.response_covered());
    assert_eq!(result.verified_embedded_signatures().len(), 2);
    Ok(())
}

#[test]
fn signed_cid_reference_is_rejected_before_content_extraction(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_reference_resolution(
        verify_signature(&cid_reference_response()?, &[SP_SIGNING_CERT.to_string()]),
        ReferenceResolutionReason::ExternalReference,
    )
}

#[test]
fn rejects_signed_request_without_root_coverage() -> Result<(), Box<dyn std::error::Error>> {
    match verify_signature(SIGNED_REQUEST, &[SP_CERT.to_string()]) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected uncovered AuthnRequest rejection, got {other:?}").into()),
    }
}

#[test]
fn rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
    // false_signed_request_sha256.xml: signature present but content tampered
    let (verified, _) = verify_signature(FALSE_SIGNED, &[SP_CERT.to_string()])?;
    assert!(!verified, "tampered message must not verify");
    Ok(())
}

#[test]
fn rolling_cert_unloadable_peer_keeps_invalid_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let garbage = "not a certificate".to_string();
    let signer = SP_CERT.to_string();
    for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
        assert_eq!(
            verify_signature(FALSE_SIGNED, &certs)?,
            (false, None),
            "unloadable leftover must not replace Invalid with Crypto"
        );
    }
    Ok(())
}

#[test]
fn detailed_rolling_cert_unloadable_peer_keeps_invalid_verdict(
) -> Result<(), Box<dyn std::error::Error>> {
    let garbage = "not a certificate".to_string();
    let signer = SP_CERT.to_string();
    for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
        let result = verify_signatures_detailed_with_profile(
            FALSE_SIGNED,
            &certs,
            None,
            XmlLimits::default(),
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?;
        assert!(
            !result.verified()
                && !result.assertion_directly_covered()
                && !result.response_covered(),
            "unloadable leftover must not replace Invalid with Crypto"
        );
    }
    Ok(())
}

#[test]
fn rolling_cert_unloadable_peer_does_not_block_valid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    // response_signed.xml is SHA-1; FIPS rejects that digest.
    let key = load_private_key(SP_PRIVKEY, None)?;
    let signed = construct_saml_signature(
        RESPONSE,
        false,
        &key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let (verified, content) = verify_signature(
        &signed,
        &["not a certificate".to_string(), SP_SIGNING_CERT.to_string()],
    )?;
    assert!(verified);
    assert!(content
        .ok_or("expected signed assertion")?
        .contains("Assertion"));
    Ok(())
}

#[test]
fn rolling_cert_key_info_naming_another_trusted_cert_still_verifies(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(SP_PRIVKEY, None)?;
    let signed = construct_saml_signature(RESPONSE, false, &key, IDP_CERT, RSA_SHA256, &[], None)?;
    let signer = SP_SIGNING_CERT.to_string();
    let named = IDP_CERT.to_string();
    for certs in [vec![signer.clone(), named.clone()], vec![named, signer]] {
        assert!(verify_signature(&signed, &certs)?.0);
        let detailed = verify_signatures_detailed_with_profile(
            &signed,
            &certs,
            None,
            XmlLimits::default(),
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?;
        assert!(detailed.verified() && detailed.assertion_directly_covered());
    }
    Ok(())
}

#[test]
fn rolling_cert_rejects_signer_outside_the_trusted_keys() -> Result<(), Box<dyn std::error::Error>>
{
    let key = load_private_key(UNTRUSTED_PRIVKEY, None)?;
    let signed = construct_saml_signature(RESPONSE, false, &key, SP_CERT, RSA_SHA256, &[], None)?;
    let certs = [SP_SIGNING_CERT.to_string(), SP_CERT.to_string()];
    assert_eq!(verify_signature(&signed, &certs)?, (false, None));
    let detailed = verify_signatures_detailed_with_profile(
        &signed,
        &certs,
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(!detailed.verified());
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn rolling_certs_and_hmac_secret_verify_only_with_their_own_key(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::binding::base64_decode;
    use crate::constants::signature_algorithm::HMAC_SHA1;
    use crate::crypto::keys::load_hmac_secret;

    let secret = HmacSecret::try_new(b"identity-provider-hmac-secret".as_slice())?;
    let certs = [SP_SIGNING_CERT.to_string(), IDP_CERT.to_string()];
    let verified = |signed: &str| -> Result<bool, SamlError> {
        Ok(verify_signatures_detailed_with_profile(
            signed,
            &certs,
            Some(&secret),
            XmlLimits::default(),
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?
        .verified())
    };
    let sign_hmac = |key_bytes: &[u8]| -> Result<String, SamlError> {
        let key = load_hmac_secret(&HmacSecret::try_new(key_bytes)?)?;
        construct_saml_signature(RESPONSE, false, &key, IDP_CERT, HMAC_SHA1, &[], None)
    };

    let rsa_key = load_private_key(SP_PRIVKEY, None)?;
    let rsa = construct_saml_signature(RESPONSE, false, &rsa_key, IDP_CERT, RSA_SHA256, &[], None)?;
    assert!(verified(&rsa)?);
    assert!(verified(&sign_hmac(secret.as_bytes())?)?);

    let base64 = normalize_cert_string(IDP_CERT);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----\n");
    for forged_key in [
        base64_decode(&base64)?,
        base64.into_bytes(),
        pem.into_bytes(),
    ] {
        assert!(!verified(&sign_hmac(&forged_key)?)?);
    }
    Ok(())
}

#[test]
fn rejects_multi_root_wrapping_attack_before_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    // attack_response_signed.xml places a forged NameID before the signed
    // response. Reject the multi-root document before signature processing.
    match verify_signature(ATTACK, &[IDP_CERT.to_string()]) {
        Err(SamlError::Xml(message)) if message == "multiple document elements" => Ok(()),
        other => Err(format!("expected multi-root XML rejection, got {other:?}").into()),
    }
}

#[test]
fn no_signature_returns_false() -> Result<(), Box<dyn std::error::Error>> {
    // a document without any Signature element verifies to (false, None)
    let (verified, content) = verify_signature(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">x</samlp:Response>",
        &[],
    )?;
    assert!(!verified);
    assert!(content.is_none());
    // keep the extractor import exercised
    let _ = extract("<a/>", &[ExtractorField::new("x", &["a"])])?;
    Ok(())
}

fn subject_confirmation_wrapping(root_open: &str, root_close: &str) -> String {
    format!(
        "{root_open}<saml:Assertion xmlns:saml=\"{assertion}\"><saml:Subject><saml:SubjectConfirmation><saml:SubjectConfirmationData><saml:Assertion/></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject></saml:Assertion>{root_close}",
        assertion = namespace::ASSERTION,
    )
}

#[test]
fn protocol_responses_reject_subject_confirmation_wrapping(
) -> Result<(), Box<dyn std::error::Error>> {
    for local_name in [
        "Response",
        "ArtifactResponse",
        "LogoutResponse",
        "ManageNameIDResponse",
        "NameIDMappingResponse",
    ] {
        let xml = subject_confirmation_wrapping(
            &format!(
                r#"<samlp:{local_name} xmlns:samlp="{protocol}">"#,
                protocol = namespace::PROTOCOL,
            ),
            &format!("</samlp:{local_name}>"),
        );
        for result in [
            verify_signature(&xml, &[]).map(|_| ()),
            verify_signatures_detailed_with_profile(
                &xml,
                &[],
                None,
                XmlLimits::default(),
                XmlSignatureProfile::AllowProviderSupportedForCompatibility,
            )
            .map(|_| ()),
        ] {
            match result {
                Err(SamlError::PotentialWrappingAttack) => {}
                other => {
                    return Err(format!(
                        "{local_name}: expected wrapping rejection, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn substring_and_foreign_namespace_roots_skip_response_wrapping(
) -> Result<(), Box<dyn std::error::Error>> {
    let protocol = namespace::PROTOCOL;
    let cases = [
        subject_confirmation_wrapping(
            &format!(r#"<samlp:FooResponse xmlns:samlp="{protocol}">"#),
            "</samlp:FooResponse>",
        ),
        subject_confirmation_wrapping(r#"<Response xmlns="urn:example:not-saml">"#, "</Response>"),
        subject_confirmation_wrapping(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:example:not-saml">"#,
            "</samlp:LogoutResponse>",
        ),
        subject_confirmation_wrapping(
            r#"<samlp:ArtifactResponse xmlns:samlp="urn:example:not-saml">"#,
            "</samlp:ArtifactResponse>",
        ),
    ];
    for xml in cases {
        let (verified, content) = verify_signature(&xml, &[])?;
        assert!(!verified && content.is_none(), "{xml}");
        let detailed = verify_signatures_detailed_with_profile(
            &xml,
            &[],
            None,
            XmlLimits::default(),
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?;
        assert!(
            !detailed.verified() && !detailed.response_covered(),
            "{xml}"
        );
    }
    Ok(())
}

fn sign_message_root(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = load_private_key(SP_PRIVKEY, None)?;
    Ok(construct_saml_signature(
        xml,
        true,
        &key,
        SP_SIGNING_CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn signed_protocol_message(
    local_name: &str,
    inner: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<samlp:{local_name} xmlns:samlp="{protocol}" xmlns:saml="{assertion}" ID="_{local_name}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>{inner}</samlp:{local_name}>"#,
        protocol = namespace::PROTOCOL,
        assertion = namespace::ASSERTION,
    );
    sign_message_root(&xml)
}

fn assert_both_verifiers_agree(
    signed: &str,
    response_covered: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let certificates = [SP_SIGNING_CERT.to_string()];
    let (verified, content) = verify_signature(signed, &certificates)?;
    assert!(verified);
    let detailed = verify_signatures_detailed_with_profile(
        signed,
        &certificates,
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(detailed.verified());
    assert_eq!(detailed.response_covered(), response_covered);
    assert!(!detailed.assertion_directly_covered());
    let detailed_content = detailed.into_signed_content();
    assert_eq!(content.as_deref(), detailed_content.as_deref());
    Ok(content)
}

#[test]
fn logout_and_artifact_responses_keep_signature_coverage() -> Result<(), Box<dyn std::error::Error>>
{
    const NESTED_ASSERTION: &str = r#"<saml:Assertion ID="_nested" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>"#;

    let logout =
        assert_both_verifiers_agree(&signed_protocol_message("LogoutResponse", "")?, true)?;
    let logout = logout.ok_or("expected signed LogoutResponse content")?;
    assert!(logout.contains("LogoutResponse"));

    let logout_assertion = assert_both_verifiers_agree(
        &signed_protocol_message("LogoutResponse", NESTED_ASSERTION)?,
        true,
    )?;
    let logout_assertion = logout_assertion.ok_or("expected LogoutResponse assertion content")?;
    assert!(logout_assertion.starts_with("<saml:Assertion"));
    assert!(!logout_assertion.contains("LogoutResponse"));

    let artifact =
        assert_both_verifiers_agree(&signed_protocol_message("ArtifactResponse", "")?, true)?;
    assert!(artifact.is_none());

    let artifact_assertion = assert_both_verifiers_agree(
        &signed_protocol_message("ArtifactResponse", NESTED_ASSERTION)?,
        true,
    )?;
    let artifact_assertion =
        artifact_assertion.ok_or("expected ArtifactResponse assertion content")?;
    assert!(artifact_assertion.starts_with("<saml:Assertion"));
    assert!(!artifact_assertion.contains("ArtifactResponse"));

    let custom = sign_message_root(
        r#"<FooResponse xmlns="urn:example:custom" ID="_foo"><Issuer>https://idp.example.com</Issuer><Assertion ID="_nested">kept</Assertion></FooResponse>"#,
    )?;
    let custom = assert_both_verifiers_agree(&custom, false)?;
    assert!(custom.is_none());
    Ok(())
}
