//! The identity provider's answer to an `AuthnRequest` whose `Version` is not
//! `2.0`.
//!
//! Core §4.1.3.1 has the responder reject a request of a major version it does
//! not support, and lets it reject a higher minor version. Core §4.1.3.2 makes
//! the error status `VersionMismatch`, bars a response version above the
//! request version, and allows a lower major version only to report
//! `RequestVersionTooHigh`. Profiles §4.1.4.1 requires the error `Response`.

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::status_code::REQUEST_VERSION_TOO_HIGH;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestRefusalReason, AuthnRequestValidationPolicy,
    CertificatePem, Credentials, EndpointUrl, EntityId, FormField, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, OutboundDelivery,
    PrivateKeyPem, Received, RefusedAuthnRequest, ReplayPolicy, RespondSso, SamlError,
    SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SsoEndpoint, StartSso, Started,
    Status, SubordinateStatusCode, X509Credential,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SECOND_ACS: &str = "https://sp.example.com/acs/second";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const SECOND_SUBJECT: &str = concat!(
    "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
    "<saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject>",
);

struct Peers {
    sp: ServiceProvider,
    idp: IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

/// An identity provider that applies `signatures`, and an `idp_descriptor`
/// with its metadata as published without a signing requirement, from which
/// the service provider also builds unsigned requests.
fn peers(signatures: AuthnRequestValidationPolicy) -> Result<Peers, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_index(0).with_default(),
        )
        .acs_endpoint(AcsEndpoint::post(SP_SECOND_ACS)?.with_index(1))
        .credentials(credentials())
        .build()?,
    );
    let idp = identity_provider(signatures)?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        identity_provider(AuthnRequestValidationPolicy::AllowUnsigned)?.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok(Peers {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn identity_provider(
    signatures: AuthnRequestValidationPolicy,
) -> Result<IdentityProvider, SamlError> {
    let validation = IdpValidationPolicy {
        authn_request_signatures: signatures,
        ..IdpValidationPolicy::default()
    };
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(credentials())
        .validation(validation)
        .build()?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

/// The request `started` posts, with its `Version` set to `version` and its
/// `AssertionConsumerServiceURL` set to the second, non-default consumer.
fn request_xml(
    started: &Started<AuthnRequest>,
    version: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let OutboundDelivery::PostForm(form) = started.outbound.delivery() else {
        return Err("expected an HTTP-POST AuthnRequest".into());
    };
    let xml = String::from_utf8(
        STANDARD.decode(form.value("SAMLRequest").ok_or("missing SAMLRequest")?)?,
    )?;
    let version_attribute = r#"Version="2.0""#;
    let acs_attribute = format!(r#"AssertionConsumerServiceURL="{SP_ACS}""#);
    if !xml.contains(version_attribute) || !xml.contains(&acs_attribute) {
        return Err("the request lacks Version 2.0 or the default ACS URL".into());
    }
    Ok(xml
        .replacen(version_attribute, &format!(r#"Version="{version}""#), 1)
        .replacen(
            &acs_attribute,
            &format!(r#"AssertionConsumerServiceURL="{SP_SECOND_ACS}""#),
            1,
        ))
}

fn signed(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sign_saml_xml(
        xml,
        true,
        &read_private_key(PRIVKEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn receive(peers: &Peers, xml: &str) -> Result<Received<AuthnRequest>, SamlError> {
    peers.idp.receive_sso(
        &peers.sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(xml.as_bytes()),
        )]),
        validation(),
    )
}

fn refused(
    peers: &Peers,
    xml: &str,
) -> Result<Box<RefusedAuthnRequest>, Box<dyn std::error::Error>> {
    match receive(peers, xml) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => Ok(refusal),
        other => Err(format!("expected refusal data, got {other:?}").into()),
    }
}

/// The status of the refusal's response as the service provider that sent
/// `started` reads it, after checking that the response went to the default
/// consumer.
fn answered_status(
    peers: &Peers,
    started: &Started<AuthnRequest>,
    refusal: &RefusedAuthnRequest,
) -> Result<Status, Box<dyn std::error::Error>> {
    let response =
        peers
            .idp
            .respond_sso_refusal(&peers.sp_descriptor, refusal, RespondSso::post())?;
    let form = response.post_form()?;
    assert_eq!(form.action().as_str(), SP_ACS);
    match peers.sp.finish_sso(
        &peers.idp_descriptor,
        &started.pending,
        Inbound::post(form.fields().to_vec()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status, .. }) => Ok(status),
        other => Err(format!("expected a correlated error status, got {other:?}").into()),
    }
}

#[test]
fn a_later_version_is_answered_with_version_mismatch_at_the_default_acs() -> TestResult {
    let peers = peers(AuthnRequestValidationPolicy::AllowUnsigned)?;
    for (version, expected) in [
        (
            "3.0",
            Status::version_mismatch()
                .with_subordinate(SubordinateStatusCode::try_new(REQUEST_VERSION_TOO_HIGH)?),
        ),
        ("2.1", Status::version_mismatch()),
    ] {
        for sign in [true, false] {
            let started = peers
                .sp
                .start_sso(&peers.idp_descriptor, StartSso::post())?;
            let xml = request_xml(&started, version)?;
            let xml = if sign { signed(&xml)? } else { xml };

            let refusal = refused(&peers, &xml)?;
            assert_eq!(
                refusal.reason(),
                AuthnRequestRefusalReason::VersionMismatch,
                "{version}, signed: {sign}",
            );
            assert_eq!(
                answered_status(&peers, &started, &refusal)?,
                expected,
                "{version}, signed: {sign}",
            );
        }
    }
    Ok(())
}

#[test]
fn a_version_refusal_comes_before_content_refusals() -> TestResult {
    let peers = peers(AuthnRequestValidationPolicy::AllowUnsigned)?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post())?;
    let xml = request_xml(&started, "3.0")?;
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    for content in [SECOND_SUBJECT, "<samlp:NameIDPolicy/>"] {
        let malformed = format!("{}{content}{}", &xml[..position], &xml[position..]);
        let refusal = refused(&peers, &signed(&malformed)?)?;
        assert_eq!(
            refusal.reason(),
            AuthnRequestRefusalReason::VersionMismatch,
            "{content}",
        );
        assert!(refusal.content_error().is_none(), "{content}");
    }
    Ok(())
}

#[test]
fn signature_and_destination_checks_come_before_the_version_refusal() -> TestResult {
    let peers = peers(AuthnRequestValidationPolicy::AllowUnsigned)?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post())?;
    let xml = request_xml(&started, "2.0")?;

    let tampered = signed(&xml)?.replacen(r#"Version="2.0""#, r#"Version="3.0""#, 1);
    assert!(matches!(
        receive(&peers, &tampered),
        Err(SamlError::SignatureVerification { .. })
    ));

    let elsewhere = request_xml(&started, "3.0")?.replacen(
        &format!(r#"Destination="{IDP_SSO_POST}""#),
        r#"Destination="https://idp.example.com/other""#,
        1,
    );
    assert!(matches!(
        receive(&peers, &signed(&elsewhere)?),
        Err(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn an_unsigned_request_that_must_be_signed_keeps_its_signature_refusal() -> TestResult {
    let peers = peers(AuthnRequestValidationPolicy::RequireSigned)?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post())?;

    let minor = refused(&peers, &request_xml(&started, "2.1")?)?;
    assert_eq!(minor.reason(), AuthnRequestRefusalReason::Unsigned);
    assert_eq!(
        answered_status(&peers, &started, &minor)?,
        Status::requester()
    );

    assert!(matches!(
        receive(&peers, &request_xml(&started, "3.0")?),
        Err(SamlError::ProtocolProfile(_))
    ));

    let major = refused(&peers, &signed(&request_xml(&started, "3.0")?)?)?;
    assert_eq!(major.reason(), AuthnRequestRefusalReason::VersionMismatch);
    Ok(())
}

#[test]
fn a_namespace_declaration_named_version_is_not_read_as_the_version() -> TestResult {
    let peers = peers(AuthnRequestValidationPolicy::AllowUnsigned)?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post())?;
    let declared = request_xml(&started, "2.0")?.replacen(
        r#"Version="2.0""#,
        r#"xmlns:Version="urn:unused" Version="2.0""#,
        1,
    );
    for xml in [declared.clone(), signed(&declared)?] {
        let received = receive(&peers, &xml)?;
        assert_eq!(
            received.message().acs_url().map(EndpointUrl::as_str),
            Some(SP_SECOND_ACS)
        );
    }
    Ok(())
}

#[test]
fn an_older_or_malformed_version_is_not_answered() -> TestResult {
    for signatures in [
        AuthnRequestValidationPolicy::AllowUnsigned,
        AuthnRequestValidationPolicy::RequireSigned,
    ] {
        let peers = peers(signatures)?;
        let started = peers
            .sp
            .start_sso(&peers.idp_descriptor, StartSso::post())?;
        for version in ["1.1", "0.9", "2", "two"] {
            for sign in [true, false] {
                let xml = request_xml(&started, version)?;
                let xml = if sign { signed(&xml)? } else { xml };
                assert!(
                    matches!(receive(&peers, &xml), Err(SamlError::ProtocolProfile(_))),
                    "{version}, signed: {sign}, {signatures:?}",
                );
            }
        }
    }
    Ok(())
}
