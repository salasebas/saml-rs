#![cfg(crypto)]

mod common;
#[path = "common/post_validation.rs"]
mod post_validation;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::attribute_name::{PAIRWISE_ID, SUBJECT_ID};
use saml_rs::constants::Binding;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeScopePolicy, AttributeValue,
    Attributes, CertificatePem, Credentials, EntityId, FormField, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpResolutionReason, Inbound, MetadataTrustPolicy, NameId, PairwiseId,
    PrivateKeyPem, ResourceLimit, RespondSso, SamlError, ServiceProvider, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoAssertion, SsoEndpoint, SubjectId, X509Credential, XmlPolicy,
};
use std::time::SystemTime;

use common::signing_credentials;
use post_validation::post_validation;

const SP: &str = "https://service.example.com/metadata";
const FIRST_IDP: &str = "https://first.example.com/metadata";
const SECOND_IDP: &str = "https://second.example.com/metadata";
const ACS: &str = "https://service.example.com/acs";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn service_provider() -> Result<ServiceProvider, SamlError> {
    let mut validation = SpValidationPolicy::default();
    validation.assertion_signatures = AssertionSignaturePolicy::RequireSigned;
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP)?, AcsEndpoint::post(ACS)?)
            .validation(validation)
            .build()?,
    ))
}

fn identity_provider(
    entity_id: &str,
    credentials: Credentials,
) -> Result<IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(entity_id)?,
            SsoEndpoint::post("https://sso.example.com/login")?,
        )
        .credentials(credentials)
        .build()?,
    ))
}

fn second_credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(include_str!("fixtures/key/idp/cert.cer")),
        PrivateKeyPem::new(include_str!(
            "fixtures/key/idp/provider_matrix_privkey.pkcs8.pem"
        )),
    ))
}

fn descriptor(idp: &IdentityProvider, entity_id: &str) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml(
        EntityId::try_new(entity_id)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )
}

fn response_fields(
    idp: &IdentityProvider,
    sp: &ServiceProvider,
    options: RespondSso,
) -> Result<Vec<FormField>, SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now()),
        options,
    )?;
    Ok(response.post_form()?.fields().to_vec())
}

#[test]
fn scoped_values_are_checked_against_only_the_assertion_issuers_policy() -> TestResult {
    const AFFILIATION: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9";
    let sp = service_provider()?;
    let first = identity_provider(FIRST_IDP, signing_credentials())?;
    let second = identity_provider(SECOND_IDP, second_credentials())?;
    let trusted = [
        descriptor(&first, FIRST_IDP)?,
        descriptor(&second, SECOND_IDP)?,
    ];
    let sp_peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    for (idp, peer, other_peer, scope, other_scope) in [
        (
            &first,
            &trusted[0],
            &trusted[1],
            "first.example.com",
            "second.example.com",
        ),
        (
            &second,
            &trusted[1],
            &trusted[0],
            "second.example.com",
            "first.example.com",
        ),
    ] {
        let foreign_subject = format!("alice@{other_scope}");
        let uppercase_scope = scope.to_ascii_uppercase();
        let uppercase_affiliation = format!("staff@{uppercase_scope}");
        let missing_local = format!("@{scope}");
        let extra_delimiter = format!("a@b@{scope}");
        let attributes = Attributes::new([
            SubjectId::try_new(&foreign_subject)?.into(),
            PairwiseId::try_new(format!("p123@{scope}"))?.into(),
            Attribute::new(
                AFFILIATION,
                [
                    AttributeValue::new(format!(" member@{scope}\n")),
                    AttributeValue::new(&uppercase_affiliation),
                    AttributeValue::new("affiliate"),
                    AttributeValue::new(&missing_local),
                    AttributeValue::new("alice@"),
                    AttributeValue::new(&extra_delimiter),
                ],
            ),
            Attribute::new("displayName", [AttributeValue::new("Alice")]),
        ]);
        let response = idp.initiate_sso(
            &sp_peer,
            SsoAssertion::new(NameId::new("alice"), SystemTime::now()).attributes(attributes),
            RespondSso::post(),
        )?;
        let session = sp.accept_unsolicited_sso_with_resolver(
            Inbound::post(response.post_form()?.fields().to_vec()),
            post_validation(&mut Default::default()),
            |issuer| {
                trusted
                    .iter()
                    .find(|idp| idp.entity_id().as_str() == issuer)
            },
        )?;

        assert_eq!(session.issuer(), peer.entity_id());
        let violations = session.scoped_attribute_violations(
            &[SUBJECT_ID, PAIRWISE_ID, AFFILIATION],
            AttributeScopePolicy::Explicit {
                issuer: peer.entity_id(),
                scopes: &[scope],
            },
        )?;
        let reported: Vec<_> = violations
            .iter()
            .map(|violation| {
                (
                    violation.attribute.name(),
                    violation.value.as_str(),
                    violation.scope,
                )
            })
            .collect();
        assert_eq!(
            reported,
            [
                (SUBJECT_ID, foreign_subject.as_str(), Some(other_scope)),
                (
                    AFFILIATION,
                    uppercase_affiliation.as_str(),
                    Some(uppercase_scope.as_str()),
                ),
                (AFFILIATION, "affiliate", None),
                (AFFILIATION, missing_local.as_str(), None),
                (AFFILIATION, "alice@", None),
                (AFFILIATION, extra_delimiter.as_str(), None),
            ]
        );
        assert!(matches!(
            session.scoped_attribute_violations(
                &[SUBJECT_ID],
                AttributeScopePolicy::Explicit {
                    issuer: other_peer.entity_id(),
                    scopes: &[other_scope]
                },
            ),
            Err(SamlError::Invalid(_)),
        ));
    }
    Ok(())
}

#[test]
fn resolves_two_trusted_idps_and_records_replay_in_the_shared_cache() -> TestResult {
    let sp = service_provider()?;
    let first = identity_provider(FIRST_IDP, signing_credentials())?;
    let second = identity_provider(SECOND_IDP, second_credentials())?;
    let trusted = [
        descriptor(&first, FIRST_IDP)?,
        descriptor(&second, SECOND_IDP)?,
    ];
    let resolve = |issuer: &str| {
        trusted
            .iter()
            .find(|idp| idp.entity_id().as_str() == issuer)
    };

    let mut cache = Default::default();
    let first_post = response_fields(&first, &sp, RespondSso::post().sign_response())?;
    let session = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(first_post.clone()),
        post_validation(&mut cache),
        resolve,
    )?;
    assert_eq!(session.issuer().as_str(), FIRST_IDP);
    assert_eq!(
        session.name_id().ok_or("missing NameID")?.value(),
        "alice@example.com"
    );
    let replay = sp.accept_unsolicited_sso(
        &trusted[0],
        Inbound::post(first_post),
        post_validation(&mut cache),
    );
    assert!(
        matches!(replay, Err(SamlError::ReplayDetected { .. })),
        "{replay:?}"
    );

    let second_post = response_fields(&second, &sp, RespondSso::post())?;
    let encoded = second_post
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .ok_or("missing SAMLResponse")?;
    let xml = String::from_utf8(STANDARD.decode(encoded.value())?)?;
    let root_issuer = format!("<saml:Issuer>{SECOND_IDP}</saml:Issuer>");
    assert!(xml.contains(&root_issuer));
    let xml = xml.replacen(&root_issuer, "", 1);
    let session = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(vec![FormField::new("SAMLResponse", STANDARD.encode(xml))]),
        post_validation(&mut cache),
        resolve,
    )?;
    assert_eq!(session.issuer().as_str(), SECOND_IDP);
    assert_eq!(
        session.name_id().ok_or("missing NameID")?.value(),
        "alice@example.com"
    );
    Ok(())
}

#[test]
fn distinguishes_unknown_idp_from_a_configured_idp_with_the_wrong_key() -> TestResult {
    let sp = service_provider()?;
    let second = identity_provider(SECOND_IDP, second_credentials())?;
    let fields = response_fields(&second, &sp, RespondSso::post().sign_response())?;
    let unknown = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(fields.clone()),
        post_validation(&mut Default::default()),
        |_| None,
    );
    assert!(
        matches!(
            unknown,
            Err(SamlError::IdpResolution {
                reason: IdpResolutionReason::UnknownEntityId,
                ..
            })
        ),
        "{unknown:?}"
    );

    let stale_metadata = identity_provider(SECOND_IDP, signing_credentials())?;
    let trusted = descriptor(&stale_metadata, SECOND_IDP)?;
    let invalid_signature = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(fields),
        post_validation(&mut Default::default()),
        |issuer| (issuer == trusted.entity_id().as_str()).then_some(&trusted),
    );
    assert!(
        matches!(
            invalid_signature,
            Err(SamlError::SignatureVerification { .. })
        ),
        "{invalid_signature:?}"
    );
    Ok(())
}

#[test]
fn reports_the_configured_and_received_ids_for_a_mismatched_descriptor() -> TestResult {
    let sp = service_provider()?;
    let first = identity_provider(FIRST_IDP, signing_credentials())?;
    let second = identity_provider(SECOND_IDP, second_credentials())?;
    let trusted = descriptor(&first, FIRST_IDP)?;
    let result = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(response_fields(&second, &sp, RespondSso::post())?),
        post_validation(&mut Default::default()),
        |_| Some(&trusted),
    );
    match result {
        Err(SamlError::IssuerMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, FIRST_IDP);
            assert_eq!(actual.as_deref(), Some(SECOND_IDP));
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn simplesign_input_is_rejected_before_lookup() -> TestResult {
    let mut called = false;
    let result = service_provider()?.accept_unsolicited_sso_with_resolver(
        Inbound::simple_sign(Vec::new()),
        post_validation(&mut Default::default()),
        |_| {
            called = true;
            None
        },
    );
    assert!(
        matches!(
            result,
            Err(SamlError::UnsupportedBinding {
                binding: Binding::SimpleSign,
                ..
            })
        ),
        "{result:?}"
    );
    assert!(!called);
    Ok(())
}

#[test]
fn refuses_ineligible_issuers_before_calling_the_resolver() -> TestResult {
    use IdpResolutionReason::{AmbiguousIssuer, InvalidIssuer, MissingIssuer};

    let sp = service_provider()?;
    let issuer = format!("<a:Issuer>{FIRST_IDP}</a:Issuer>");
    let assertion = format!("<a:Assertion>{issuer}</a:Assertion>");
    for (children, expected) in [
        (
            format!("<p:Extensions>{issuer}</p:Extensions>"),
            MissingIssuer,
        ),
        (format!("<p:Issuer>{FIRST_IDP}</p:Issuer>"), MissingIssuer),
        (format!("<ds:Signature/>{assertion}"), MissingIssuer),
        (format!("{assertion}<a:EncryptedAssertion/>"), MissingIssuer),
        (format!("{issuer}{issuer}"), AmbiguousIssuer),
        (
            format!("{assertion}<a:Assertion><a:Issuer>{SECOND_IDP}</a:Issuer></a:Assertion>"),
            AmbiguousIssuer,
        ),
        (format!("<a:Issuer/>{assertion}"), InvalidIssuer),
        (
            format!("<a:Issuer Format=\"urn:example:other\">{FIRST_IDP}</a:Issuer>"),
            InvalidIssuer,
        ),
        ("<a:Issuer>relative-id</a:Issuer>".into(), InvalidIssuer),
    ] {
        let xml = format!(
            r#"<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{children}</p:Response>"#,
        );
        let mut called = false;
        let result = sp.accept_unsolicited_sso_with_resolver(
            Inbound::post(vec![FormField::new("SAMLResponse", STANDARD.encode(xml))]),
            post_validation(&mut Default::default()),
            |_| {
                called = true;
                None
            },
        );
        assert!(
            matches!(result, Err(SamlError::IdpResolution { reason, .. }) if reason == expected),
            "expected {expected:?} for {children}, got {result:?}",
        );
        assert!(!called, "{children}");
    }
    Ok(())
}

#[test]
fn enforces_configured_xml_limit_before_calling_the_resolver() -> TestResult {
    let mut xml = XmlPolicy::default();
    xml.limits.max_bytes = 32;
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP)?, AcsEndpoint::post(ACS)?)
            .xml(xml)
            .build()?,
    );
    let idp = identity_provider(FIRST_IDP, signing_credentials())?;
    let mut called = false;
    let result = sp.accept_unsolicited_sso_with_resolver(
        Inbound::post(response_fields(&idp, &sp, RespondSso::post())?),
        post_validation(&mut Default::default()),
        |_| {
            called = true;
            None
        },
    );
    assert!(
        matches!(
            result,
            Err(SamlError::LimitExceeded {
                limit: ResourceLimit::Base64DecodedBytes,
                maximum: 32,
                ..
            })
        ),
        "{result:?}",
    );
    assert!(!called);
    Ok(())
}
