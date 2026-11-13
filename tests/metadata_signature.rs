#![cfg(crypto)]

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{
    construct_saml_signature, verify_metadata_signature, verify_metadata_signature_detailed,
    verify_metadata_signature_detailed_with_limits, verify_metadata_signature_with_limits,
};
use saml_rs::entity::{SignatureAction, SignatureConfig};
use saml_rs::metadata::IdpMetadata;
use saml_rs::util::normalize_cert_string;
use saml_rs::xml::XmlLimits;
use saml_rs::SamlError;

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const WRONG_CERT: &str = include_str!("fixtures/key/idp/cert.cer");
const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";

fn idp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_md1" entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
}

fn sign_root_metadata(xml: &str) -> Result<String, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], Some(&config))
}

fn signed_non_metadata_root() -> Result<String, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='Root']".into()),
        action: SignatureAction::Prepend,
    };
    construct_saml_signature(
        r#"<Root ID="_root"><Payload>signed</Payload></Root>"#,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        Some(&config),
    )
}

fn signed_child_metadata() -> Result<String, Box<dyn std::error::Error>> {
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_signed_child\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(CERT),
    );
    let template = format!(
        "<EntityDescriptor ID=\"_evil_root\" entityID=\"https://evil.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signature}<IDPSSODescriptor ID=\"_signed_child\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://trusted.example.com/sso\"/></IDPSSODescriptor></EntityDescriptor>"
    );
    let key = load_private_key(PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

fn metadata_with_xpath_transform_signature_template() -> Result<String, Box<dyn std::error::Error>>
{
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    Ok(format!(
        "<EntityDescriptor ID=\"_md1\" entityID=\"https://idp.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"{dsig}\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_md1\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{xpath}\"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.example.com/sso\"/></IDPSSODescriptor></EntityDescriptor>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        xpath = XPATH_TRANSFORM,
        digest = digest,
        cert = normalize_cert_string(CERT),
    ))
}

#[test]
fn metadata_signature_detailed_default_limits_preserves_signed_descriptor(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let verification = verify_metadata_signature_detailed(&signed, &[CERT.to_string()])?;

    assert!(verification.verified());
    let signed_xml = verification
        .signed_entity_descriptor_xml()
        .ok_or("missing signed descriptor")?;
    assert!(signed_xml.contains("entityID=\"https://idp.example.com/metadata\""));
    assert!(signed_xml.contains("<ds:Signature"));
    Ok(())
}

#[test]
fn metadata_signature_bool_wrapper_uses_detailed_coverage() -> Result<(), Box<dyn std::error::Error>>
{
    let signed = sign_root_metadata(idp_metadata_xml())?;

    assert!(verify_metadata_signature(&signed, &[CERT.to_string()])?);
    assert!(verify_metadata_signature_with_limits(
        &signed,
        &[CERT.to_string()],
        XmlLimits::default(),
    )?);

    let limits = XmlLimits {
        max_bytes: signed.len() - 1,
        ..XmlLimits::default()
    };
    for result in [
        verify_metadata_signature_with_limits(&signed, &[CERT.to_string()], limits),
        verify_metadata_signature_detailed_with_limits(&signed, &[CERT.to_string()], limits)
            .map(|verification| verification.verified()),
    ] {
        assert!(
            matches!(result, Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED"))
        );
    }

    let oversized = format!(
        "{}{}",
        " ".repeat(saml_rs::xml::dom::DEFAULT_XML_MAX_BYTES),
        signed
    );
    for result in [
        verify_metadata_signature(&oversized, &[CERT.to_string()]),
        verify_metadata_signature_detailed(&oversized, &[CERT.to_string()])
            .map(|verification| verification.verified()),
    ] {
        assert!(
            matches!(result, Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED"))
        );
    }
    Ok(())
}

#[test]
fn metadata_method_detailed_default_limits_preserves_signed_descriptor(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let metadata = IdpMetadata::from_xml(&signed)?;
    let certificates = [CERT.to_string()];
    let verification = metadata.verify_signature_detailed(&certificates)?;

    assert_eq!(
        verification,
        verify_metadata_signature_detailed(&signed, &certificates)?
    );
    assert_eq!(
        metadata.verify_signature_detailed_with_limits(&certificates, XmlLimits::default())?,
        verification
    );
    assert!(metadata.verify_signature(&certificates)?);
    assert!(metadata.verify_signature_with_limits(&certificates, XmlLimits::default())?);

    let limits = XmlLimits {
        max_bytes: signed.len() - 1,
        ..XmlLimits::default()
    };
    for result in [
        metadata.verify_signature_with_limits(&certificates, limits),
        metadata
            .verify_signature_detailed_with_limits(&certificates, limits)
            .map(|verification| verification.verified()),
    ] {
        assert!(
            matches!(result, Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED"))
        );
    }

    assert!(verification
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("entityID=\"https://idp.example.com/metadata\"")));
    Ok(())
}

#[test]
fn metadata_signature_unsigned_metadata_returns_unverified(
) -> Result<(), Box<dyn std::error::Error>> {
    let verification = verify_metadata_signature_detailed_with_limits(
        idp_metadata_xml(),
        &[CERT.to_string()],
        XmlLimits::default(),
    )?;

    assert!(!verification.verified());
    assert_eq!(verification.signed_entity_descriptor_xml(), None);
    Ok(())
}

#[test]
fn metadata_signature_does_not_verify_with_a_certificate_outside_the_trust_anchors(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let verification = verify_metadata_signature_detailed(&signed, &[WRONG_CERT.to_string()])?;

    assert!(!verification.verified());
    assert_eq!(verification.signed_entity_descriptor_xml(), None);
    Ok(())
}

#[test]
fn metadata_signature_rejects_signed_child_without_descriptor_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped = signed_child_metadata()?;

    match verify_metadata_signature_detailed_with_limits(
        &wrapped,
        &[CERT.to_string()],
        XmlLimits::default(),
    ) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}

#[test]
fn metadata_signature_rejects_xpath_reference_transform() -> Result<(), Box<dyn std::error::Error>>
{
    let metadata = metadata_with_xpath_transform_signature_template()?;

    match verify_metadata_signature_detailed(&metadata, &[CERT.to_string()]) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}

#[test]
fn metadata_signature_rejects_signed_non_metadata_root() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_non_metadata_root()?;

    match verify_metadata_signature_detailed(&signed, &[CERT.to_string()]) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}
