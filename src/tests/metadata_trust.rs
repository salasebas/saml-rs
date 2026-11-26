#![cfg(crypto)]

use std::time::SystemTime;
use std::time::{Duration, UNIX_EPOCH};

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::constants::attribute_name::{PAIRWISE_ID, SUBJECT_ID};
use saml_rs::constants::digest_algorithm::SHA256;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{namespace, transform_algorithm};
use saml_rs::crypto::keys::read_private_key;
use saml_rs::crypto::sign_saml_xml;
use saml_rs::error::SignatureVerificationReason;
use saml_rs::tests::signature_relocation::{relocate_signature, Relocation};
use saml_rs::util::normalize_cert_string;
use saml_rs::XmlPolicy;
use saml_rs::{
    AttributeScopePolicy, Attributes, CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy,
    PairwiseId, RespondSso, SamlError, SpDescriptor, SsoAssertion, SubjectId,
};

use super::identifier_formats::{alice, exchange};

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

mod aggregate;

fn idp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_idp_md1" entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
}

fn sp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_sp_md1" entityID="https://sp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
}

fn sign_root_metadata(xml: &str) -> Result<String, SamlError> {
    sign_metadata_root(xml, &[])
}

fn sign_metadata_root(xml: &str, transforms: &[String]) -> Result<String, SamlError> {
    let key = read_private_key(PRIVKEY, None)?;
    sign_saml_xml(xml, true, &key, CERT, RSA_SHA256, transforms, None)
}

fn signed_child_metadata() -> Result<String, Box<dyn std::error::Error>> {
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_signed_child\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        digest = SHA256,
        cert = normalize_cert_string(CERT),
    );
    let template = format!(
        "<EntityDescriptor ID=\"_evil_root\" entityID=\"https://evil.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signature}<IDPSSODescriptor ID=\"_signed_child\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://trusted.example.com/sso\"/></IDPSSODescriptor></EntityDescriptor>"
    );
    let key = read_private_key(PRIVKEY, None)?;
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

fn trust_allowing_inclusive_canonicalization<'a>(
    certificates: &'a [CertificatePem],
) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignatureAllowingInclusiveCanonicalization {
        trusted_certificates: certificates,
    }
}

fn trust_allowing_weak_algorithms<'a>(
    certificates: &'a [CertificatePem],
) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms {
        trusted_certificates: certificates,
    }
}

fn import_idp(xml: &str, policy: MetadataTrustPolicy<'_>) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml(
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
    let descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    let signed_xml = descriptor
        .signed_metadata_xml()
        .ok_or("missing signed descriptor")?;
    assert!(signed_xml.contains("https://idp.example.com/metadata"));
    assert!(signed_xml.contains("<ds:Signature"));

    let other_certificate =
        CertificatePem::new(include_str!("../../tests/fixtures/key/idp/cert.cer"));
    let result = import_idp(&signed, trust(&[other_certificate]));
    assert!(matches!(
        result,
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature
        })
    ));
    Ok(())
}

#[test]
fn require_signature_counts_only_xml_signature_elements() -> Result<(), Box<dyn std::error::Error>>
{
    const FOREIGN_SIGNATURE: &str = r#"<Extensions><ext:Signature xmlns:ext="urn:example:ext">publisher seal</ext:Signature></Extensions>"#;
    let unsigned = idp_metadata_xml().replacen(
        "<IDPSSODescriptor",
        &format!("{FOREIGN_SIGNATURE}<IDPSSODescriptor"),
        1,
    );
    let signed = sign_root_metadata(&unsigned)?;
    let key_info = "<ds:KeyInfo>";
    let with_foreign_object = signed.replacen(
        key_info,
        &format!(r#"{key_info}<ext:Object xmlns:ext="urn:example:ext"/>"#),
        1,
    );
    assert_ne!(with_foreign_object, signed);
    let cert = CertificatePem::new(CERT);

    for xml in [&signed, &with_foreign_object] {
        let descriptor = import_idp(xml, trust(std::slice::from_ref(&cert)))?;
        assert!(descriptor
            .signed_metadata_xml()
            .is_some_and(|signed_xml| signed_xml.contains(FOREIGN_SIGNATURE)));
    }
    Ok(())
}

#[test]
fn metadata_scopes_require_a_current_registration_authority_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = idp_metadata_xml()
        .replacen(
            "<EntityDescriptor ",
            r#"<EntityDescriptor validUntil="2030-01-01T00:00:00Z" "#,
            1,
        )
        .replacen(
            "<IDPSSODescriptor ",
            concat!(
                r#"<Extensions xmlns:s="urn:mace:shibboleth:metadata:1.0">"#,
                r#"<s:Scope regexp="false">example.com</s:Scope>"#,
                r#"<s:Scope regexp="true">regex.example.com</s:Scope>"#,
                "</Extensions><IDPSSODescriptor ",
            ),
            1,
        );
    let peer_signed = sign_root_metadata(&xml)?;
    let peer_certificates = [CertificatePem::new(CERT)];
    let authority_certificate = include_str!("../../tests/fixtures/key/idp/cert.cer");
    let authority_certificates = [CertificatePem::new(authority_certificate)];
    let authority_policy = MetadataTrustPolicy::RequireRegistrationAuthoritySignature {
        trusted_certificates: &authority_certificates,
    };
    let authority_key = read_private_key(
        include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem"),
        None,
    )?;
    let authority_signed = sign_saml_xml(
        &xml,
        true,
        &authority_key,
        authority_certificate,
        RSA_SHA256,
        &[],
        None,
    )?;
    let idp = import_idp(&authority_signed, authority_policy)?;
    let signed_by_peer = import_idp(&peer_signed, trust(&peer_certificates))?;
    let unverified = import_idp(&authority_signed, MetadataTrustPolicy::Unverified)?;
    assert!(signed_by_peer.signed_metadata_xml().is_some());
    assert!(matches!(
        import_idp(&peer_signed, authority_policy),
        Err(SamlError::SignatureVerification { .. })
    ));

    let session = exchange(
        SsoAssertion::new(alice(), SystemTime::now()).attributes(Attributes::new([
            SubjectId::try_new("alice@example.com")?.into(),
            PairwiseId::try_new("pairwise@regex.example.com")?.into(),
        ])),
        RespondSso::post(),
    )?
    .session;

    let valid_until = UNIX_EPOCH + Duration::from_secs(1_893_456_000);
    let before_expiration = valid_until - Duration::from_secs(1);
    let names = [SUBJECT_ID, PAIRWISE_ID];
    let violations = session.scoped_attribute_violations(
        &names,
        AttributeScopePolicy::RegistrationAuthority {
            idp: &idp,
            now: before_expiration,
        },
    )?;
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].attribute.name(), PAIRWISE_ID);
    assert_eq!(violations[0].scope, Some("regex.example.com"));
    let verified_scopes = idp.scopes()?;
    for idp in [&signed_by_peer, &unverified] {
        assert_eq!(idp.scopes()?, verified_scopes);
        assert!(matches!(
            session.scoped_attribute_violations(
                &names,
                AttributeScopePolicy::RegistrationAuthority {
                    idp,
                    now: before_expiration
                },
            ),
            Err(SamlError::Invalid(_))
        ));
    }
    assert!(matches!(
        session.scoped_attribute_violations(
            &names,
            AttributeScopePolicy::RegistrationAuthority {
                idp: &idp,
                now: valid_until
            },
        ),
        Err(SamlError::TimeWindowInvalid { .. })
    ));
    Ok(())
}

#[test]
fn metadata_trust_accepts_signed_sp_descriptor_with_pinned_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_root_metadata(sp_metadata_xml())?;
    let descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    assert!(descriptor.signed_metadata_xml().is_some());
    assert!(descriptor
        .signed_metadata_xml()
        .is_some_and(|xml| xml.contains("https://sp.example.com/metadata")));
    Ok(())
}

#[test]
fn signed_descriptor_import_honors_the_configured_byte_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = XmlPolicy::default();
    let padding = " ".repeat(policy.limits.max_bytes);
    let certificates = [CertificatePem::new(CERT)];

    let signed_idp = sign_root_metadata(idp_metadata_xml())?;
    let idp_xml = format!("{padding}{signed_idp}");
    policy.limits.max_bytes = idp_xml.len();
    let idp = IdpDescriptor::from_metadata_xml_with_xml_policy(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_xml,
        trust(&certificates),
        &policy,
    )?;
    assert_eq!(idp.signed_metadata_xml(), Some(signed_idp.as_str()));

    let signed_sp = sign_root_metadata(sp_metadata_xml())?;
    let sp_xml = format!("{padding}{signed_sp}");
    policy.limits.max_bytes = sp_xml.len();
    let sp = SpDescriptor::from_metadata_xml_with_xml_policy(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &sp_xml,
        trust(&certificates),
        &policy,
    )?;
    assert_eq!(sp.signed_metadata_xml(), Some(signed_sp.as_str()));
    Ok(())
}

#[test]
fn metadata_trust_rejects_unsigned_metadata_when_signature_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    match IdpDescriptor::from_metadata_xml(
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

    match IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://evil.example.com/metadata")?,
        &wrapped,
        trust(std::slice::from_ref(&cert)),
    ) {
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
        trust_allowing_inclusive_canonicalization(std::slice::from_ref(&cert)),
    )
}

#[test]
fn relaxed_policy_accepts_inclusive_canonicalization() -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_metadata_root(
        idp_metadata_xml(),
        &[
            transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
            INCLUSIVE_C14N.to_string(),
        ],
    )?;

    assert_signature_shape_rejected(&signed, trust(std::slice::from_ref(&cert)))?;

    let descriptor = import_idp(
        &signed,
        trust_allowing_inclusive_canonicalization(std::slice::from_ref(&cert)),
    )?;
    assert!(descriptor.signed_metadata_xml().is_some());
    assert!(descriptor
        .signed_metadata_xml()
        .is_some_and(|xml| xml.contains("https://idp.example.com/metadata")));
    Ok(())
}

#[test]
fn allowing_weak_algorithms_keeps_the_profile_transforms() -> Result<(), Box<dyn std::error::Error>>
{
    let cert = CertificatePem::new(CERT);
    let certificates = std::slice::from_ref(&cert);
    let profile = sign_root_metadata(idp_metadata_xml())?;
    assert!(
        import_idp(&profile, trust_allowing_weak_algorithms(certificates))?
            .signed_metadata_xml()
            .is_some()
    );

    let inclusive = sign_metadata_root(
        idp_metadata_xml(),
        &[
            transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
            INCLUSIVE_C14N.to_string(),
        ],
    )?;
    assert_signature_shape_rejected(&inclusive, trust_allowing_weak_algorithms(certificates))
}

#[test]
fn allowing_inclusive_canonicalization_keeps_identifier_and_single_reference_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let policy = trust_allowing_inclusive_canonicalization(std::slice::from_ref(&cert));
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
fn require_signature_rejects_ds_object_even_when_inclusive_canonicalization_is_allowed(
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
        trust_allowing_inclusive_canonicalization(std::slice::from_ref(&cert)),
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
        Err(SamlError::SignatureVerification { .. } | SamlError::Crypto { .. }) => Ok(()),
        other => Err(format!("expected cryptographic rejection, got {other:?}").into()),
    }
}

#[test]
fn entities_descriptor_require_signature_accepts_the_profile_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let xml = entities_document(Some("_group1"), "").replace(
        "entityID=\"https://idp.example.com/metadata\"",
        "entityID=\" https://idp.example.com/metadata \"",
    );
    let signed = sign_metadata_root(&xml, &[])?;
    let descriptor = import_idp(&signed, trust(std::slice::from_ref(&cert)))?;

    assert_eq!(descriptor.signed_metadata_xml(), Some(signed.as_str()));
    assert_eq!(
        descriptor
            .single_sign_on_location(saml_rs::SsoRequestBinding::Post)?
            .as_ref()
            .map(saml_rs::EndpointUrl::as_str),
        Some("https://idp.example.com/sso")
    );
    Ok(())
}

#[test]
fn signed_aggregate_import_reads_the_group_entity_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let document = format!(
        r#"<EntitiesDescriptor ID="_group1" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{dsig}"><Extensions><mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>https://refeds.org/sirtfi</saml:AttributeValue></saml:Attribute></mdattr:EntityAttributes></Extensions><EntityDescriptor entityID="https://idp.example.com/metadata">{role}</EntityDescriptor></EntitiesDescriptor>"#,
        dsig = namespace::DSIG,
        role = idp_role(),
    );
    let signed = sign_metadata_root(&document, &[])?;

    let descriptor = import_idp(&signed, trust(std::slice::from_ref(&cert)))?;

    assert!(descriptor.signed_metadata_xml().is_some());
    assert_eq!(
        descriptor.entity_attributes()?.assurance_certifications(),
        ["https://refeds.org/sirtfi"]
    );
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
    match IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &xml,
        MetadataTrustPolicy::Unverified,
    ) {
        Err(SamlError::Xml { message, .. })
            if message == "metadata has more than one EntityDescriptor" =>
        {
            Ok(())
        }
        other => Err(
            format!("expected multiple entity descriptors to be rejected, got {other:?}").into(),
        ),
    }
}

#[test]
fn unverified_import_does_not_record_a_metadata_signature_as_verified(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        MetadataTrustPolicy::Unverified,
    )?;

    assert!(!descriptor.signed_metadata_xml().is_some());
    assert_eq!(descriptor.signed_metadata_xml(), None);
    Ok(())
}

#[test]
fn require_signature_rejects_a_nested_signature_ahead_of_the_root_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = read_private_key(PRIVKEY, None)?;
    let nested = relocate_signature(
        &sign_saml_xml(idp_metadata_xml(), true, &key, CERT, RSA_SHA256, &[], None)?,
        &["EntityDescriptor", "IDPSSODescriptor"],
        Relocation::FirstChildOf,
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
const RSA_1024_KEY: &str = include_str!("../../tests/fixtures/key/rsa1024/privkey.pkcs8.pem");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const RSA_1024_CERT: &str = include_str!("../../tests/fixtures/key/rsa1024/cert.pem");

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
    manager.add_key(read_private_key(key_pem, None)?);
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
            trust_allowing_inclusive_canonicalization(certificates),
        ] {
            match import_idp(&signed, policy).map(|idp| idp.signed_metadata_xml().is_some()) {
                Err(SamlError::AlgorithmUnsupported) => {}
                other => failures.push(format!(
                    "{signature_method} with {digest_method} under {policy:?}: {other:?}"
                )),
            }
        }
        let compatible = import_idp(&signed, trust_allowing_weak_algorithms(certificates))?;
        assert!(compatible.signed_metadata_xml().is_some());
    }

    if !failures.is_empty() {
        return Err(failures.join("\n").into());
    }

    let sha1 = sign_idp_metadata_with(dsig::RSA_SHA1, dsig::SHA1, PRIVKEY, CERT)?;
    for policy in [
        trust(certificates),
        trust_allowing_inclusive_canonicalization(certificates),
    ] {
        assert!(import_idp(&sha1, policy)?.signed_metadata_xml().is_some());
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
        trust_allowing_inclusive_canonicalization(only_short),
    ] {
        match import_idp(&signed, policy).map(|idp| idp.signed_metadata_xml().is_some()) {
            Err(SamlError::Crypto { message, .. }) if message.contains("1024-bit RSA key") => {}
            other => return Err(format!("{policy:?}: {other:?}").into()),
        }
    }

    let compatible = import_idp(&signed, trust_allowing_weak_algorithms(only_short))?;
    assert!(compatible.signed_metadata_xml().is_some());

    let with_usable_key = [short, CertificatePem::new(CERT)];
    match import_idp(&signed, trust(&with_usable_key))
        .map(|idp| idp.signed_metadata_xml().is_some())
    {
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }) => Ok(()),
        other => Err(format!("expected signature verification failure, got {other:?}").into()),
    }
}
