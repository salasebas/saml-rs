#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::constants::digest_algorithm::SHA256;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
use saml_rs::crypto::construct_saml_signature;
use saml_rs::crypto::keys::load_private_key;
use saml_rs::entity::{SignatureAction, SignatureConfig};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy, SamlError, SpDescriptor,
};

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn idp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_idp_md1" entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
}

fn sp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_sp_md1" entityID="https://sp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
}

fn sign_root_metadata(xml: &str) -> Result<String, SamlError> {
    sign_metadata_root(xml, "EntityDescriptor", &[])
}

fn sign_metadata_root(
    xml: &str,
    root_local_name: &str,
    transforms: &[String],
) -> Result<String, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let reference = format!("/*[local-name(.)='{root_local_name}']");
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some(reference),
        action: SignatureAction::Prepend,
    };
    construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, transforms, Some(&config))
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

const INCLUSIVE_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";

fn trust<'a>(certificates: &'a [CertificatePem]) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: certificates,
    }
}

fn trust_allowing_other_transforms<'a>(
    certificates: &'a [CertificatePem],
) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignatureAllowingOtherCanonicalization {
        trusted_certificates: certificates,
    }
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
fn trust_allowing_weak_algorithms<'a>(
    certificates: &'a [CertificatePem],
) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithmsForCompatibility {
        trusted_certificates: certificates,
    }
}

fn import_idp(xml: &str, policy: MetadataTrustPolicy<'_>) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        xml,
        policy,
    )
}

fn assert_signature_shape_rejected(
    xml: &str,
    policy: MetadataTrustPolicy<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    match import_idp(xml, policy) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}

fn idp_role() -> &'static str {
    r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor>"#
}

fn reference_xml(uri: &str, transforms: &[&str]) -> String {
    let transforms_xml: String = transforms
        .iter()
        .map(|algorithm| format!(r#"<ds:Transform Algorithm="{algorithm}"/>"#))
        .collect();
    format!(
        r#"<ds:Reference URI="{uri}"><ds:Transforms>{transforms_xml}</ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"#
    )
}

fn signature_xml(references: &str, include_object: bool) -> String {
    let object = if include_object {
        "<ds:Object>unsigned</ds:Object>"
    } else {
        ""
    };
    format!(
        r#"<ds:Signature xmlns:ds="{dsig}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{exc_c14n}"/><ds:SignatureMethod Algorithm="{sig_alg}"/>{references}</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue>{object}</ds:Signature>"#,
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
    )
}

fn entity_document(identifier: Option<&str>, signature: &str) -> String {
    let identifier = identifier
        .map(|identifier| format!(r#" ID="{identifier}""#))
        .unwrap_or_default();
    format!(
        r#"<EntityDescriptor{identifier} entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{dsig}">{signature}{role}</EntityDescriptor>"#,
        dsig = namespace::DSIG,
        role = idp_role(),
    )
}

fn entities_document(identifier: Option<&str>, signature: &str) -> String {
    let identifier = identifier
        .map(|identifier| format!(r#" ID="{identifier}""#))
        .unwrap_or_default();
    format!(
        r#"<EntitiesDescriptor{identifier} xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{dsig}">{signature}<EntityDescriptor entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">{role}</EntityDescriptor></EntitiesDescriptor>"#,
        dsig = namespace::DSIG,
        role = idp_role(),
    )
}

fn profile_signature(identifier: &str) -> String {
    signature_xml(
        &reference_xml(
            &format!("#{identifier}"),
            &[
                transform_algorithm::ENVELOPED_SIGNATURE,
                transform_algorithm::EXC_C14N,
            ],
        ),
        false,
    )
}

#[test]
fn metadata_trust_accepts_signed_idp_descriptor_with_pinned_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    assert!(descriptor.was_verified_with_pinned_certificates());
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("https://idp.example.com/metadata")));
    Ok(())
}

#[test]
fn metadata_trust_accepts_signed_sp_descriptor_with_pinned_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_root_metadata(sp_metadata_xml())?;
    let descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    assert!(descriptor.was_verified_with_pinned_certificates());
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("https://sp.example.com/metadata")));
    Ok(())
}

#[test]
fn metadata_trust_rejects_unsigned_metadata_when_signature_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    match IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp_metadata_xml(),
        trust(std::slice::from_ref(&cert)),
    ) {
        Err(SamlError::SignatureVerification { reason }) => {
            assert_eq!(reason, SignatureVerificationReason::XmlSignature);
            Ok(())
        }
        other => Err(format!("expected metadata signature failure, got {other:?}").into()),
    }
}

#[test]
fn metadata_trust_rejects_signature_without_descriptor_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let wrapped = signed_child_metadata()?;

    match IdpDescriptor::from_metadata_xml(&wrapped, trust(std::slice::from_ref(&cert))) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}

#[test]
fn require_signature_rejects_signed_root_without_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = entity_document(None, &profile_signature("_md1"));
    assert_signature_shape_rejected(
        &xml,
        trust(std::slice::from_ref(&CertificatePem::new(CERT))),
    )
}

#[test]
fn require_signature_rejects_a_reference_that_is_not_a_single_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let policy = trust(std::slice::from_ref(&cert));
    let wrong_uri = entity_document(
        Some("_md1"),
        &signature_xml(
            &reference_xml(
                "#other",
                &[
                    transform_algorithm::ENVELOPED_SIGNATURE,
                    transform_algorithm::EXC_C14N,
                ],
            ),
            false,
        ),
    );
    assert_signature_shape_rejected(&wrong_uri, policy)?;

    let two_references = entity_document(
        Some("_md1"),
        &signature_xml(
            &format!(
                "{}{}",
                reference_xml(
                    "#_md1",
                    &[
                        transform_algorithm::ENVELOPED_SIGNATURE,
                        transform_algorithm::EXC_C14N,
                    ],
                ),
                reference_xml(
                    "#_md1",
                    &[
                        transform_algorithm::ENVELOPED_SIGNATURE,
                        transform_algorithm::EXC_C14N,
                    ],
                ),
            ),
            false,
        ),
    );
    assert_signature_shape_rejected(&two_references, policy)
}

#[test]
fn require_signature_rejects_a_signature_that_is_not_enveloped(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = entity_document(
        Some("_md1"),
        &signature_xml(
            &reference_xml("#_md1", &[transform_algorithm::EXC_C14N]),
            false,
        ),
    );
    assert_signature_shape_rejected(
        &xml,
        trust(std::slice::from_ref(&CertificatePem::new(CERT))),
    )
}

#[test]
fn require_signature_rejects_a_transform_other_than_enveloped_and_exclusive_canonicalization(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let xml = entity_document(
        Some("_md1"),
        &signature_xml(
            &reference_xml(
                "#_md1",
                &[
                    transform_algorithm::ENVELOPED_SIGNATURE,
                    XPATH_TRANSFORM,
                    transform_algorithm::EXC_C14N,
                ],
            ),
            false,
        ),
    );
    assert_signature_shape_rejected(&xml, trust(std::slice::from_ref(&cert)))?;
    assert_signature_shape_rejected(
        &xml,
        trust_allowing_other_transforms(std::slice::from_ref(&cert)),
    )
}

#[test]
fn require_signature_allowing_other_transforms_accepts_inclusive_canonicalization(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_metadata_root(
        idp_metadata_xml(),
        "EntityDescriptor",
        &[
            transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
            INCLUSIVE_C14N.to_string(),
        ],
    )?;

    assert_signature_shape_rejected(&signed, trust(std::slice::from_ref(&cert)))?;

    let descriptor = import_idp(
        &signed,
        trust_allowing_other_transforms(std::slice::from_ref(&cert)),
    )?;
    assert!(descriptor.was_verified_with_pinned_certificates());
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("https://idp.example.com/metadata")));
    Ok(())
}

#[test]
fn allowing_other_transforms_keeps_identifier_and_single_reference_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let policy = trust_allowing_other_transforms(std::slice::from_ref(&cert));
    let missing_identifier = entity_document(
        None,
        &signature_xml(
            &reference_xml(
                "#_md1",
                &[transform_algorithm::ENVELOPED_SIGNATURE, INCLUSIVE_C14N],
            ),
            false,
        ),
    );
    assert_signature_shape_rejected(&missing_identifier, policy)?;

    let two_references = entity_document(
        Some("_md1"),
        &signature_xml(
            &format!(
                "{}{}",
                reference_xml(
                    "#_md1",
                    &[transform_algorithm::ENVELOPED_SIGNATURE, INCLUSIVE_C14N,],
                ),
                reference_xml(
                    "#_md1",
                    &[transform_algorithm::ENVELOPED_SIGNATURE, INCLUSIVE_C14N],
                ),
            ),
            false,
        ),
    );
    assert_signature_shape_rejected(&two_references, policy)?;

    let not_enveloped = entity_document(
        Some("_md1"),
        &signature_xml(&reference_xml("#_md1", &[INCLUSIVE_C14N]), false),
    );
    assert_signature_shape_rejected(&not_enveloped, policy)
}

#[test]
fn require_signature_rejects_ds_object_even_when_other_transforms_are_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let xml = entity_document(
        Some("_md1"),
        &signature_xml(
            &reference_xml(
                "#_md1",
                &[
                    transform_algorithm::ENVELOPED_SIGNATURE,
                    transform_algorithm::EXC_C14N,
                ],
            ),
            true,
        ),
    );
    assert_signature_shape_rejected(&xml, trust(std::slice::from_ref(&cert)))?;
    assert_signature_shape_rejected(
        &xml,
        trust_allowing_other_transforms(std::slice::from_ref(&cert)),
    )
}

#[test]
fn exclusive_canonicalization_with_comments_is_part_of_the_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = entity_document(
        Some("_md1"),
        &signature_xml(
            &reference_xml(
                "#_md1",
                &[
                    transform_algorithm::ENVELOPED_SIGNATURE,
                    transform_algorithm::EXC_C14N_WITH_COMMENTS,
                ],
            ),
            false,
        ),
    );
    match import_idp(
        &xml,
        trust(std::slice::from_ref(&CertificatePem::new(CERT))),
    ) {
        Err(SamlError::SignedReferenceMismatch) => {
            Err("exclusive canonicalization with comments was rejected as another transform".into())
        }
        Err(SamlError::SignatureVerification { .. } | SamlError::Crypto(_)) => Ok(()),
        other => Err(format!("expected cryptographic rejection, got {other:?}").into()),
    }
}

#[test]
fn entities_descriptor_require_signature_accepts_the_profile_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_metadata_root(
        &entities_document(Some("_group1"), ""),
        "EntitiesDescriptor",
        &[],
    )?;
    let descriptor = import_idp(&signed, trust(std::slice::from_ref(&cert)))?;

    assert!(descriptor.was_verified_with_pinned_certificates());
    assert_eq!(
        descriptor
            .metadata()
            .get_single_sign_on_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| {
            xml.contains("EntitiesDescriptor") && xml.contains("https://idp.example.com/metadata")
        }));
    Ok(())
}

#[test]
fn entities_descriptor_is_held_to_the_same_signature_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let policy = trust(std::slice::from_ref(&cert));
    assert_signature_shape_rejected(
        &entities_document(None, &profile_signature("_group1")),
        policy,
    )?;
    assert_signature_shape_rejected(
        &entities_document(
            Some("_group1"),
            &signature_xml(
                &reference_xml(
                    "#other",
                    &[
                        transform_algorithm::ENVELOPED_SIGNATURE,
                        transform_algorithm::EXC_C14N,
                    ],
                ),
                false,
            ),
        ),
        policy,
    )?;
    assert_signature_shape_rejected(
        &entities_document(
            Some("_group1"),
            &signature_xml(
                &reference_xml("#_group1", &[transform_algorithm::EXC_C14N]),
                false,
            ),
        ),
        policy,
    )?;
    assert_signature_shape_rejected(
        &entities_document(
            Some("_group1"),
            &signature_xml(
                &reference_xml(
                    "#_group1",
                    &[transform_algorithm::ENVELOPED_SIGNATURE, XPATH_TRANSFORM],
                ),
                false,
            ),
        ),
        policy,
    )
}

#[test]
fn entities_descriptor_import_rejects_two_entities() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp.example.com/metadata">{role}</EntityDescriptor><EntityDescriptor entityID="https://other.example.com/metadata">{role}</EntityDescriptor></EntitiesDescriptor>"#,
        role = idp_role(),
    );
    match IdpDescriptor::from_metadata_xml(&xml, MetadataTrustPolicy::UnsignedForCompatibility) {
        Err(SamlError::Xml(message))
            if message.contains("ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR") =>
        {
            Ok(())
        }
        other => Err(
            format!("expected multiple entity descriptors to be rejected, got {other:?}").into(),
        ),
    }
}

#[test]
fn unsigned_for_compatibility_does_not_record_a_signature_as_verified(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    assert!(!descriptor.was_verified_with_pinned_certificates());
    assert_eq!(descriptor.signed_entity_descriptor_xml(), None);
    Ok(())
}

#[test]
fn require_signature_rejects_a_nested_signature_ahead_of_the_root_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some(
            "/*[local-name(.)='EntityDescriptor']/*[local-name(.)='IDPSSODescriptor']".into(),
        ),
        action: SignatureAction::Prepend,
    };
    let nested = construct_saml_signature(
        idp_metadata_xml(),
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        Some(&config),
    )?;
    let close = "</EntityDescriptor>";
    let end = nested
        .rfind(close)
        .ok_or("signed metadata is missing its closing tag")?;
    let with_decoy = format!(
        "{}{}{}",
        &nested[..end],
        profile_signature("_idp_md1"),
        &nested[end..]
    );
    let cert = CertificatePem::new(CERT);
    let policy = trust(std::slice::from_ref(&cert));

    assert_signature_shape_rejected(&nested, policy)?;
    assert_signature_shape_rejected(&with_decoy, policy)
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const RSA_1024_KEY: &str = include_str!("fixtures/key/rsa1024/privkey.pkcs8.pem");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const RSA_1024_CERT: &str = include_str!("fixtures/key/rsa1024/cert.pem");

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
fn sign_idp_metadata_with(
    signature_method: &str,
    digest_method: &str,
    key_pem: &str,
    cert_pem: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{signature_method}\"/><ds:Reference URI=\"#_idp_md1\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest_method}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(cert_pem),
    );
    let template = entity_document(Some("_idp_md1"), &signature);
    let mut manager = KeysManager::new();
    manager.add_key(load_private_key(key_pem, None)?);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn require_signature_rejects_md5_and_ripemd160_metadata_signatures(
) -> Result<(), Box<dyn std::error::Error>> {
    use bergshamra::core::algorithm as dsig;

    let cert = CertificatePem::new(CERT);
    let certificates = std::slice::from_ref(&cert);
    let mut failures = Vec::new();
    for (signature_method, digest_method) in [
        (dsig::RSA_MD5, dsig::SHA256),
        (dsig::RSA_RIPEMD160, dsig::SHA256),
        (dsig::RSA_SHA256, dsig::MD5),
        (dsig::RSA_SHA256, dsig::RIPEMD160),
    ] {
        let signed = sign_idp_metadata_with(signature_method, digest_method, PRIVKEY, CERT)?;
        for policy in [
            trust(certificates),
            trust_allowing_other_transforms(certificates),
        ] {
            match import_idp(&signed, policy).map(|idp| idp.was_verified_with_pinned_certificates())
            {
                Err(SamlError::AlgorithmUnsupported) => {}
                other => failures.push(format!(
                    "{signature_method} with {digest_method} under {policy:?}: {other:?}"
                )),
            }
        }
        let compatible = import_idp(&signed, trust_allowing_weak_algorithms(certificates))?;
        assert!(compatible.was_verified_with_pinned_certificates());
        assert!(saml_rs::crypto::verify_metadata_signature(
            &signed,
            &[CERT.to_string()]
        )?);
    }

    if !failures.is_empty() {
        return Err(failures.join("\n").into());
    }

    let sha1 = sign_idp_metadata_with(dsig::RSA_SHA1, dsig::SHA1, PRIVKEY, CERT)?;
    for policy in [
        trust(certificates),
        trust_allowing_other_transforms(certificates),
    ] {
        assert!(import_idp(&sha1, policy)?.was_verified_with_pinned_certificates());
    }
    Ok(())
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn require_signature_does_not_verify_with_a_1024_bit_rsa_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let short = CertificatePem::new(RSA_1024_CERT);
    let signed = sign_idp_metadata_with(RSA_SHA256, SHA256, RSA_1024_KEY, RSA_1024_CERT)?;
    let only_short = std::slice::from_ref(&short);
    for policy in [
        trust(only_short),
        trust_allowing_other_transforms(only_short),
    ] {
        match import_idp(&signed, policy).map(|idp| idp.was_verified_with_pinned_certificates()) {
            Err(SamlError::Crypto(message)) if message.contains("1024-bit RSA key") => {}
            other => return Err(format!("{policy:?}: {other:?}").into()),
        }
    }

    let compatible = import_idp(&signed, trust_allowing_weak_algorithms(only_short))?;
    assert!(compatible.was_verified_with_pinned_certificates());
    assert!(saml_rs::crypto::verify_metadata_signature(
        &signed,
        &[RSA_1024_CERT.to_string()]
    )?);

    let with_usable_key = [short, CertificatePem::new(CERT)];
    match import_idp(&signed, trust(&with_usable_key))
        .map(|idp| idp.was_verified_with_pinned_certificates())
    {
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }) => Ok(()),
        other => Err(format!("expected signature verification failure, got {other:?}").into()),
    }
}
