//! Enhanced Client/Proxy login over PAOS.
//!
//! The enhanced client in this file is the test double for that role. It is
//! not a service-provider or identity-provider facade.

#![cfg(crypto)]

#[path = "paos_sso/schema_validation.rs"]
mod schema_validation;

#[path = "paos_sso/authn_context.rs"]
mod authn_context;

#[path = "paos_sso/relay_state.rs"]
mod relay_state;

#[path = "paos_sso/request_refusals.rs"]
mod request_refusals;

use std::time::{Duration, SystemTime};

use roxmltree::{Document, Node};
use saml_rs::constants::{status_code::AUTHN_FAILED, transform_algorithm};
use saml_rs::{
    check_paos_client_headers, AcsEndpoint, AlgorithmPolicy, Attribute, AttributeNameFormat,
    AttributeValue, Attributes, AuthnContextReference, EndpointUrl, EntityId, IdentityProvider,
    IdpConfig, IdpConfigBuilder, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId,
    NameIdFormat, PaosHttpResponse, RelayState, ReplayPolicy, SamlError, SamlValidationContext,
    ServiceProvider, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion,
    SsoEndpoint, SsoOutcome, StartPaosSso, Status, SubordinateStatusCode, TransformAlgorithm,
    X509Credential,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs/post";
const IDP_SOAP: &str = "https://idp.example.com/sso/soap";
const ECP_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
const PAOS_MEDIA_TYPE: &str = "application/vnd.paos+xml";
const PAOS_HEADER: &str =
    "ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

struct EnhancedClient {
    response_consumer_url: String,
    relay_state: Option<String>,
}

fn credentials() -> saml_rs::Credentials {
    saml_rs::Credentials::default().with_signing_credential(X509Credential::new(
        saml_rs::CertificatePem::new(CERT),
        saml_rs::PrivateKeyPem::new(PRIVKEY),
    ))
}

type Parties = (
    saml_rs::ServiceProvider,
    saml_rs::IdentityProvider,
    SpDescriptor,
    IdpDescriptor,
);

fn idp_builder() -> Result<IdpConfigBuilder, SamlError> {
    Ok(IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post("https://idp.example.com/sso/post")?,
    ))
}

fn parties() -> Result<Parties, SamlError> {
    parties_with(idp_builder()?)
}

fn parties_with(idp: IdpConfigBuilder) -> Result<Parties, SamlError> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(credentials())
        .validation(SpValidationPolicy::default())
        .build()?,
    );
    let idp = IdentityProvider::new(
        idp.credentials(credentials())
            .validation(IdpValidationPolicy::default())
            .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn principal() -> NameId {
    NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
}

fn enhanced_client_takes_authn_request(
    sp_soap: &str,
) -> Result<(EnhancedClient, String), Box<dyn std::error::Error>> {
    let document = Document::parse(sp_soap)?;
    let header = child(document.root_element(), "Header").ok_or("SOAP header missing")?;
    let paos_request = header
        .children()
        .find(|node| node.attribute("responseConsumerURL").is_some())
        .ok_or("paos:Request missing")?;
    let response_consumer_url = paos_request
        .attribute("responseConsumerURL")
        .ok_or("responseConsumerURL missing")?
        .to_string();
    let relay_state =
        child(header, "RelayState").map(|node| node.text().unwrap_or_default().to_string());
    let authn = body_element(sp_soap, document.root_element(), "AuthnRequest")?;
    let forwarded = soap_envelope("", &authn);
    Ok((
        EnhancedClient {
            response_consumer_url,
            relay_state,
        },
        forwarded,
    ))
}

fn enhanced_client_takes_response(
    client: &EnhancedClient,
    idp_soap: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let document = Document::parse(idp_soap)?;
    let header = child(document.root_element(), "Header").ok_or("SOAP header missing")?;
    let ecp_response = header
        .children()
        .find(|node| node.attribute("AssertionConsumerServiceURL").is_some())
        .ok_or("ecp:Response missing")?;
    let assertion_consumer = ecp_response
        .attribute("AssertionConsumerServiceURL")
        .ok_or("AssertionConsumerServiceURL missing")?;
    if assertion_consumer != client.response_consumer_url {
        return Err("assertion consumer does not match responseConsumerURL".into());
    }
    let response = body_element(idp_soap, document.root_element(), "Response")?;
    let relay = client
        .relay_state
        .as_ref()
        .map(|value| relay_state_header(value))
        .unwrap_or_default();
    Ok(soap_envelope(&relay, &response))
}

fn soap_envelope(header_xml: &str, body_xml: &str) -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_NS}\"><SOAP-ENV:Header>{header_xml}</SOAP-ENV:Header><SOAP-ENV:Body>{body_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

fn relay_state_header(value: &str) -> String {
    format!(
        "<ecp:RelayState xmlns:ecp=\"{ECP_PROFILE}\" SOAP-ENV:mustUnderstand=\"1\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/actor/next\">{value}</ecp:RelayState>"
    )
}

fn body_element(
    xml: &str,
    envelope: Node,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = child(envelope, "Body").ok_or("SOAP body missing")?;
    let element = child(body, name).ok_or(name)?;
    let slice = xml.get(element.range()).ok_or("element offsets")?;
    Ok(slice.to_string())
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| child.has_tag_name(name))
}

#[test]
fn enhanced_client_completes_paos_login() -> Result<(), Box<dyn std::error::Error>> {
    let mut algorithms = AlgorithmPolicy::default();
    algorithms.signed_reference_transforms = vec![
        TransformAlgorithm::EnvelopedSignature,
        TransformAlgorithm::CanonicalXml,
    ];
    let (sp, idp, sp_descriptor, idp_descriptor) =
        parties_with(idp_builder()?.algorithms(algorithms))?;
    check_paos_client_headers(PAOS_MEDIA_TYPE, PAOS_HEADER)?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .relay_state(RelayState::try_new("state")?)
            .provider_name("Example SP"),
    )?;
    assert_eq!(started.http_response.http_status(), 200);
    assert!(started
        .http_response
        .headers()
        .iter()
        .any(|header| header.name() == "Content-Type" && header.value() == PAOS_MEDIA_TYPE));
    assert!(started.http_response.envelope().contains(ECP_PROFILE));
    assert!(!started
        .http_response
        .envelope()
        .contains("ProtocolBinding="));

    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    assert_eq!(client.response_consumer_url, SP_ACS);
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    assert_eq!(answered.http_status(), 200);
    assert!(answered.headers().iter().any(
        |header| header.name() == "Content-Type" && header.value() == "text/xml; charset=utf-8"
    ));

    let document = Document::parse(answered.envelope())?;
    let mut transforms = document.root_element();
    for name in [
        "Body",
        "Response",
        "Signature",
        "SignedInfo",
        "Reference",
        "Transforms",
    ] {
        transforms = child(transforms, name).ok_or(name)?;
    }
    assert_eq!(
        transforms
            .children()
            .filter(|transform| transform.is_element())
            .map(|transform| transform.attribute("Algorithm"))
            .collect::<Vec<_>>(),
        [
            Some(transform_algorithm::ENVELOPED_SIGNATURE),
            Some(transform_algorithm::EXC_C14N),
        ],
        "browser transforms must not leak into the SOAP-contained PAOS response"
    );

    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let pending = saml_rs::PendingPaosSso::from_snapshot(started.pending.snapshot())?;
    let session = sp.finish_paos_sso(&idp_descriptor, &pending, &sp_request, validation())?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(session.verified_xml_signatures().len(), 1);
    assert_eq!(pending.acs_url(), &EndpointUrl::try_new(SP_ACS)?);
    assert_eq!(answered.session_index(), None);
    Ok(())
}

#[test]
fn paos_response_returns_the_session_index_the_service_provider_accepts(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties_with(
        idp_builder()?.slo_endpoint(SloEndpoint::redirect("https://idp.example.com/slo")?),
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;

    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let pending = saml_rs::PendingPaosSso::from_snapshot(started.pending.snapshot())?;
    let session = sp.finish_paos_sso(&idp_descriptor, &pending, &sp_request, validation())?;
    let accepted = session
        .logout_subject()
        .ok_or("accepted session is missing a logout subject")?;
    assert_eq!(
        answered.session_index().map(std::slice::from_ref),
        Some(accepted.session_indexes())
    );
    Ok(())
}

#[test]
fn failed_authentication_does_not_establish_a_session() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let authn_failed =
        Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTHN_FAILED)?);
    let rejected = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(authn_failed.clone()),
    )?;
    assert_eq!(rejected.http_status(), 200);
    assert!(!rejected.envelope().contains("Assertion>"));
    let sp_request = enhanced_client_takes_response(&client, rejected.envelope())?;
    match sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation()) {
        Err(SamlError::StatusNotSuccess { status, .. }) => assert_eq!(status, authn_failed),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("an error status does not return a session".into()),
    }
    Ok(())
}

#[test]
fn an_empty_or_blank_envelope_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    for envelope in ["", " \n\t"] {
        let received = idp.receive_paos_sso(
            &sp_descriptor,
            envelope,
            &EndpointUrl::try_new(IDP_SOAP)?,
            validation(),
        );
        assert!(
            matches!(received, Err(SamlError::Xml { .. })),
            "{envelope:?}: {received:?}"
        );
        let finished =
            sp.finish_paos_sso(&idp_descriptor, &started.pending, envelope, validation());
        assert!(
            matches!(finished, Err(SamlError::Xml { .. })),
            "{envelope:?}: {finished:?}"
        );
    }
    Ok(())
}

#[test]
fn failure_response_with_a_success_status_is_not_written() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    match idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(Status::success()),
    ) {
        Err(SamlError::Invalid(_)) => Ok(()),
        Err(error) => Err(format!("expected Invalid, got {error:?}").into()),
        Ok(_) => Err("a Success status without an assertion is not written".into()),
    }
}

#[test]
fn returned_relay_state_must_match_the_value_the_service_provider_sent(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .relay_state(RelayState::try_new("state")?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let mut sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    sp_request = sp_request.replace(&relay_state_header("state"), "");
    let error =
        match sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation()) {
            Err(error) => error,
            Ok(_) => return Err("a missing relay state does not match".into()),
        };
    assert!(matches!(error, SamlError::RelayStateMismatch { .. }));
    Ok(())
}

#[test]
fn destination_must_be_the_soap_endpoint_that_received_the_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let error = match idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new("https://idp.example.com/elsewhere")?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("a different SOAP endpoint does not match Destination".into()),
    };
    assert!(matches!(error, SamlError::DestinationMismatch { .. }));
    Ok(())
}

#[test]
fn unpublished_assertion_consumer_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _, _, idp_descriptor) = parties()?;
    let error = match sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .acs_url(EndpointUrl::try_new("https://evil.example/acs")?)
            .allow_unsigned_authn_request(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an unpublished assertion consumer is rejected".into()),
    };
    assert!(matches!(error, SamlError::Invalid(_)));
    Ok(())
}

#[test]
fn unprocessable_soap_is_a_client_fault() -> Result<(), Box<dyn std::error::Error>> {
    let (_, idp, sp_descriptor, _) = parties()?;
    let envelope = format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_NS}\"><SOAP-ENV:Body><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_1\"></samlp:AuthnRequest><samlp:Extra xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"></samlp:Extra></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    );
    let error = match idp.receive_paos_sso(
        &sp_descriptor,
        &envelope,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("two SOAP body elements are not one AuthnRequest".into()),
    };
    assert!(matches!(error, SamlError::ProtocolProfile(_)));

    let fault = PaosHttpResponse::soap_fault();
    assert_eq!(fault.http_status(), 500);
    assert!(fault.envelope().contains("SOAP-ENV:Fault"));
    assert!(fault.envelope().contains("SOAP-ENV:Client"));
    assert!(fault.headers().iter().any(
        |header| header.name() == "Content-Type" && header.value() == "text/xml; charset=utf-8"
    ));
    Ok(())
}

#[test]
fn unpublished_assertion_consumer_on_the_request_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let tampered = idp_request.replace(SP_ACS, "https://evil.example/acs");
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &tampered,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let error =
        match idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal())) {
            Err(error) => error,
            Ok(_) => return Err("an unpublished assertion consumer is rejected".into()),
        };
    assert!(matches!(error, SamlError::Invalid(_)));
    Ok(())
}

#[test]
fn caller_authentication_instant_is_checked_and_written() -> Result<(), Box<dyn std::error::Error>>
{
    const AUTHENTICATED: &str = "2026-01-01T08:00:00Z";
    let authenticated = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_254_400);
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()).with_authn_instant(authenticated),
    )?;
    assert!(answered
        .envelope()
        .contains(&format!("AuthnInstant=\"{AUTHENTICATED}\"")));

    let later = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal())
            .with_authn_instant(SystemTime::now() + Duration::from_secs(3600)),
    );
    assert!(
        matches!(&later, Err(SamlError::Invalid(message)) if message.contains("later than the response IssueInstant")),
        "{later:?}"
    );
    Ok(())
}

#[test]
fn requested_sp_name_qualifier_is_checked_and_written() -> Result<(), Box<dyn std::error::Error>> {
    const AFFILIATION: &str = "https://affiliation.example.com";
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let requested = idp_request.replace(
        "<samlp:NameIDPolicy ",
        &format!("<samlp:NameIDPolicy SPNameQualifier=\"{AFFILIATION}\" "),
    );
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &requested,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let unqualified =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()));
    assert!(
        matches!(&unqualified, Err(SamlError::Invalid(message)) if message.contains(AFFILIATION)),
        "{unqualified:?}"
    );

    let qualified = NameId::new("alice@example.com")
        .with_format(NameIdFormat::EmailAddress)
        .with_name_qualifier(IDP_ENTITY_ID)
        .with_sp_name_qualifier(AFFILIATION);
    let mismatched = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(qualified.clone().with_format(NameIdFormat::Persistent)),
    );
    assert!(matches!(
        mismatched,
        Err(SamlError::NameIdPolicyFormatMismatch {
            requested: NameIdFormat::EmailAddress,
            issued: Some(NameIdFormat::Persistent),
            ..
        })
    ));
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(qualified))?;
    assert!(answered.envelope().contains(&format!(
        "<saml:NameID NameQualifier=\"{IDP_ENTITY_ID}\" SPNameQualifier=\"{AFFILIATION}\" Format=\"{}\">alice@example.com</saml:NameID>",
        NameIdFormat::EmailAddress.as_uri()
    )));
    Ok(())
}

#[test]
fn requested_subject_is_the_only_subject_issued() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let requested = idp_request.replace(
        "<samlp:NameIDPolicy ",
        &format!(
            "<saml:Subject><saml:NameID Format=\"{}\">alice@example.com</saml:NameID></saml:Subject><samlp:NameIDPolicy ",
            NameIdFormat::EmailAddress.as_uri()
        ),
    );
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &requested,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let other = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(NameId::new("bob@example.com").with_format(NameIdFormat::EmailAddress)),
    );
    assert!(
        matches!(&other, Err(SamlError::Invalid(message)) if message.contains("requested Subject")),
        "{other:?}"
    );

    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    assert!(answered.envelope().contains(&format!(
        "<saml:NameID Format=\"{}\">alice@example.com</saml:NameID>",
        NameIdFormat::EmailAddress.as_uri()
    )));
    Ok(())
}

#[test]
fn response_name_id_format_that_is_not_an_absolute_uri_is_not_sent(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let subject =
        NameId::new("alice@example.com").with_format(NameIdFormat::Custom("local-format".into()));
    match idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(subject)) {
        Err(SamlError::Invalid(message)) if message.contains("absolute URI reference") => Ok(()),
        Err(error) => Err(format!("unexpected {error:?}").into()),
        Ok(_) => Err("a relative NameID format is not sent".into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn cbc_encrypted_response_is_signed() -> Result<(), Box<dyn std::error::Error>> {
    let mut encryption = saml_rs::XmlPolicy::default();
    encryption.encryption.assertions = saml_rs::AssertionEncryptionPolicy::EncryptAssertions;
    let encrypted_credentials =
        credentials().with_decryption_credential(saml_rs::X509Credential::new(
            saml_rs::CertificatePem::new(CERT),
            saml_rs::PrivateKeyPem::new(PRIVKEY),
        ));
    let mut sp_validation = SpValidationPolicy::default();
    sp_validation.assertions = saml_rs::AssertionSignaturePolicy::RequireSigned;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(encrypted_credentials)
        .validation(sp_validation)
        .xml(encryption)
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post("https://idp.example.com/sso/post")?,
        )
        .credentials(credentials())
        .validation(IdpValidationPolicy::default())
        .xml(encryption)
        .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    assert!(answered.envelope().contains("EncryptedAssertion"));
    assert!(answered.envelope().contains("<ds:Signature"));
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session =
        sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation())?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn relay_state_is_checked_after_the_response_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .relay_state(RelayState::try_new("state")?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    // Break the response signature without touching the SOAP relay state header.
    let tampered = sp_request.replace("alice@example.com", "mallory@example.com");
    assert_ne!(sp_request, tampered);
    let with_expected_relay = sp
        .finish_paos_sso(&idp_descriptor, &started.pending, &tampered, validation())
        .err()
        .ok_or("a broken response signature does not return a session")?;
    let mut wrong_snapshot = started.pending.snapshot();
    wrong_snapshot.relay_state = Some("other".to_string());
    let wrong_pending = saml_rs::PendingPaosSso::from_snapshot(wrong_snapshot)?;
    let with_wrong_relay = sp
        .finish_paos_sso(&idp_descriptor, &wrong_pending, &tampered, validation())
        .err()
        .ok_or("a broken response signature does not return a session")?;
    // A wrong relay state must not surface while the signature is broken: the
    // expected value cannot be probed without a valid signature.
    assert!(!matches!(
        with_wrong_relay,
        SamlError::RelayStateMismatch { .. }
    ));
    assert_eq!(
        std::mem::discriminant(&with_expected_relay),
        std::mem::discriminant(&with_wrong_relay)
    );
    Ok(())
}

#[test]
fn overlong_echo_is_rejected_before_the_response_status() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .relay_state(RelayState::try_new("state")?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(Status::responder()),
    )?;
    let document = Document::parse(answered.envelope())?;
    let response = body_element(answered.envelope(), document.root_element(), "Response")?;
    let long = "r".repeat(81);
    let sp_request = soap_envelope(&relay_state_header(&long), &response);
    let error =
        match sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation()) {
            Err(error) => error,
            Ok(_) => return Err("an overlong relay state is rejected".into()),
        };
    assert!(matches!(error, SamlError::Invalid(_)));
    Ok(())
}

#[test]
fn signed_request_with_a_namespace_declared_on_the_envelope_is_received(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    assert!(idp_request.contains("<ds:Signature"));
    let declaration = " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"";
    let hoisted = idp_request.replacen(declaration, "", 1).replacen(
        "<SOAP-ENV:Envelope",
        &format!("<SOAP-ENV:Envelope{declaration}"),
        1,
    );
    assert_ne!(hoisted, idp_request);
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &hoisted,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().id(), started.pending.request_id());
    Ok(())
}

#[test]
fn signed_response_with_namespaces_declared_on_the_envelope_is_finished(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let declaration = " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"";
    let hoisted = sp_request.replacen(declaration, "", 1).replacen(
        "<SOAP-ENV:Body",
        &format!("<SOAP-ENV:Body{declaration}"),
        1,
    );
    assert_ne!(hoisted, sp_request);
    let session = sp.finish_paos_sso(&idp_descriptor, &started.pending, &hoisted, validation())?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn relay_state_xml_forbids_is_rejected_at_start() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _, _, idp_descriptor) = parties()?;
    for relay_state in ["a\u{1}b", "a\u{FFFE}b"] {
        let error = match sp.start_paos_sso(
            &idp_descriptor,
            StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
                .relay_state(RelayState::try_new(relay_state.to_string())?)
                .allow_unsigned_authn_request(),
        ) {
            Err(error) => error,
            Ok(_) => return Err("a relay state XML 1.0 forbids is rejected".into()),
        };
        assert!(matches!(error, SamlError::Invalid(_)));
    }
    Ok(())
}

#[test]
fn provider_name_is_checked_at_start_like_web_browser_sso() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, _, _, idp_descriptor) = parties()?;
    let start = |provider_name: &str| {
        sp.start_paos_sso(
            &idp_descriptor,
            StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
                .provider_name(provider_name)
                .allow_unsigned_authn_request(),
        )
    };
    let empty = start("")?;
    assert!(empty.http_response.envelope().contains("ProviderName=\"\""));
    match start("a\u{FFFF}b") {
        Err(SamlError::Invalid(_)) => Ok(()),
        Err(error) => Err(format!("expected Invalid, got {error:?}").into()),
        Ok(_) => Err("a ProviderName with a character XML 1.0 forbids is not sent".into()),
    }
}

#[test]
fn protocol_binding_naming_paos_is_received() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let with_binding = idp_request.replacen(
        " AssertionConsumerServiceURL=",
        " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:PAOS\" AssertionConsumerServiceURL=",
        1,
    );
    assert_ne!(with_binding, idp_request);
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &with_binding,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().protocol_binding(), None);
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    assert_eq!(answered.http_status(), 200);
    Ok(())
}

#[test]
fn protocol_binding_naming_http_artifact_is_not_received() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let with_binding = idp_request.replacen(
        " AssertionConsumerServiceURL=",
        " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" AssertionConsumerServiceURL=",
        1,
    );
    assert_ne!(with_binding, idp_request);
    assert!(matches!(
        idp.receive_paos_sso(
            &sp_descriptor,
            &with_binding,
            &EndpointUrl::try_new(IDP_SOAP)?,
            validation(),
        ),
        Err(SamlError::UnsupportedBinding {
            binding: saml_rs::constants::Binding::Artifact,
            ..
        })
    ));
    Ok(())
}

#[test]
fn assertion_consumer_of_a_binding_that_cannot_carry_the_response_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let artifact_acs = "https://sp.example.com/acs/artifact";
    let metadata = sp_descriptor.metadata_xml().replacen(
        "</SPSSODescriptor>",
        &format!(
            "<AssertionConsumerService index=\"7\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"{artifact_acs}\"/></SPSSODescriptor>"
        ),
        1,
    );
    assert_ne!(metadata, sp_descriptor.metadata_xml());
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    for tampered in [
        idp_request.replace(SP_ACS, artifact_acs),
        idp_request.replace(
            &format!(" AssertionConsumerServiceURL=\"{SP_ACS}\""),
            " AssertionConsumerServiceIndex=\"7\"",
        ),
    ] {
        assert_ne!(tampered, idp_request);
        let received = idp.receive_paos_sso(
            &sp_descriptor,
            &tampered,
            &EndpointUrl::try_new(IDP_SOAP)?,
            validation(),
        )?;
        let error =
            match idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal())) {
                Err(error) => error,
                Ok(_) => return Err("an HTTP-Artifact assertion consumer is rejected".into()),
            };
        assert!(matches!(error, SamlError::Invalid(_)));
    }
    Ok(())
}

#[test]
fn attributes_reach_the_service_provider_session() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let mail = Attribute::new(
        "urn:oid:0.9.2342.19200300.100.1.3",
        vec![AttributeValue::new("alice@example.com")],
    )
    .with_name_format(AttributeNameFormat::Uri);
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()).with_attributes(Attributes::new(vec![mail.clone()])),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session =
        sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation())?;
    assert_eq!(session.attributes().as_slice(), [mail]);
    Ok(())
}

#[test]
fn request_without_an_assertion_consumer_is_answered_at_the_metadata_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let metadata = sp_descriptor.metadata_xml().replacen(
        "<AssertionConsumerService ",
        "<AssertionConsumerService index=\"9\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/acs/other\"/><AssertionConsumerService ",
        1,
    );
    assert_ne!(metadata, sp_descriptor.metadata_xml());
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let without_selector =
        idp_request.replace(&format!(" AssertionConsumerServiceURL=\"{SP_ACS}\""), "");
    assert_ne!(without_selector, idp_request);
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &without_selector,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().acs_url(), None);
    assert_eq!(received.message().acs_index(), None);

    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session =
        sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation())?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let rejected = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(
            Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTHN_FAILED)?),
        ),
    )?;
    let sp_request = enhanced_client_takes_response(&client, rejected.envelope())?;
    assert!(matches!(
        sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation(),),
        Err(SamlError::StatusNotSuccess { .. })
    ));

    let artifact_default = sp_descriptor.metadata_xml().replacen(
        "<AssertionConsumerService ",
        "<AssertionConsumerService index=\"8\" isDefault=\"true\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"https://sp.example.com/acs/artifact\"/><AssertionConsumerService ",
        1,
    );
    let artifact_sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &artifact_default,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let received = idp.receive_paos_sso(
        &artifact_sp,
        &without_selector,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    assert!(matches!(
        idp.respond_paos_sso(&artifact_sp, &received, SsoAssertion::new(principal())),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn assertion_matching_an_outstanding_logout_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let outstanding = saml_rs::OutstandingLogout::try_new(
        NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress),
        Vec::new(),
        saml_rs::SamlInstant::try_new("2999-01-01T00:00:00Z")?,
    )?;
    let error = match sp.finish_paos_sso_with_outstanding_logout(
        &idp_descriptor,
        &started.pending,
        &sp_request,
        validation(),
        &outstanding,
    ) {
        Err(error) => error,
        Ok(_) => return Err("an assertion matching an outstanding logout is rejected".into()),
    };
    assert!(matches!(
        error,
        SamlError::AssertionMatchesOutstandingLogout
    ));
    Ok(())
}

const WSSE_SECURITY_HEADER: &str = "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" SOAP-ENV:mustUnderstand=\"1\"/>";

#[test]
fn identity_provider_refuses_a_header_it_must_understand_and_does_not_process(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let sp_soap = started.http_response.envelope();
    let document = Document::parse(sp_soap)?;
    let authn = body_element(sp_soap, document.root_element(), "AuthnRequest")?;
    let idp_request = soap_envelope(WSSE_SECURITY_HEADER, &authn);
    let error = match idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an unprocessed mustUnderstand header is refused".into()),
    };
    assert!(matches!(error, SamlError::Xml { .. }), "{error:?}");
    Ok(())
}

#[test]
fn service_provider_refuses_a_header_it_must_understand_and_does_not_process(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let document = Document::parse(answered.envelope())?;
    let response = body_element(answered.envelope(), document.root_element(), "Response")?;
    let sp_request = soap_envelope(WSSE_SECURITY_HEADER, &response);
    let error =
        match sp.finish_paos_sso(&idp_descriptor, &started.pending, &sp_request, validation()) {
            Err(error) => error,
            Ok(_) => return Err("an unprocessed mustUnderstand header is refused".into()),
        };
    assert!(matches!(error, SamlError::Xml { .. }), "{error:?}");
    Ok(())
}

#[test]
fn service_provider_processes_relay_state_and_paos_response_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?)
            .relay_state(RelayState::try_new("state")?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let document = Document::parse(answered.envelope())?;
    let response = body_element(answered.envelope(), document.root_element(), "Response")?;
    let paos_response = "<paos:Response xmlns:paos=\"urn:liberty:paos:2003-08\" SOAP-ENV:mustUnderstand=\"1\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/actor/next\"/>";
    let other_actor_state = format!(
        r#"<ecp:RelayState xmlns:ecp="{ECP_PROFILE}" SOAP-ENV:actor="urn:example:router">router state</ecp:RelayState>"#
    );
    let headers = format!(
        "{other_actor_state}{paos_response}{}",
        relay_state_header("state")
    );
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &soap_envelope(&headers, &response),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}
