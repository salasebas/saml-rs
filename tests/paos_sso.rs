//! Enhanced Client/Proxy login over PAOS.
//!
//! The enhanced client in this file is the test double for that role. It is
//! not a service-provider or identity-provider facade.

#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::{Duration, SystemTime};

use saml_rs::constants::status_code::AUTH_FAILED;
use saml_rs::xml::dom::{parse, Node};
use saml_rs::{
    AcsEndpoint, Attribute, AttributeNameFormat, AttributeValue, Attributes, AuthnContextReference,
    EndpointUrl, EntityId, IdpConfig, IdpConfigBuilder, IdpDescriptor, IdpValidationPolicy,
    MetadataTrustPolicy, NameId, NameIdFormat, PaosAuthnRequest, PaosClientRequest,
    PaosSsoResponse, RelayStateParam, ReplayPolicy, RespondPaosSso, Saml, SamlError,
    SamlValidationContext, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
    StartPaosSso, Status, Subject, SubjectConfirmation, SubordinateStatusCode,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs/post";
const IDP_SOAP: &str = "https://idp.example.com/sso/soap";
const ECP_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

struct EnhancedClient {
    response_consumer_url: String,
    relay_state: Option<String>,
}

fn credentials() -> saml_rs::Credentials {
    saml_rs::Credentials {
        signing_key: Some(saml_rs::PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(saml_rs::CertificatePem::new(CERT)),
        ..saml_rs::Credentials::default()
    }
}

type Parties = (
    Saml<saml_rs::Sp>,
    Saml<saml_rs::Idp>,
    SpDescriptor,
    IdpDescriptor,
);

fn parties() -> Result<Parties, SamlError> {
    parties_with(IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?))
}

fn parties_with(idp: IdpConfigBuilder) -> Result<Parties, SamlError> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        idp.sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso/post")?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(
        NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress)),
        Vec::new(),
    )
}

fn enhanced_client_takes_authn_request(
    sp_soap: &str,
) -> Result<(EnhancedClient, String), Box<dyn std::error::Error>> {
    let document = parse(sp_soap)?;
    let header = child(&document.root, "Header").ok_or("SOAP header missing")?;
    let paos_request = header
        .children
        .iter()
        .find(|node| node.attr("responseConsumerURL").is_some())
        .ok_or("paos:Request missing")?;
    let response_consumer_url = paos_request
        .attr("responseConsumerURL")
        .ok_or("responseConsumerURL missing")?
        .to_string();
    let relay_state = header
        .children
        .iter()
        .find(|node| node.local_name == "RelayState")
        .map(|node| node.text.clone());
    let authn = body_element(sp_soap, &document.root, "AuthnRequest")?;
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
    let document = parse(idp_soap)?;
    let header = child(&document.root, "Header").ok_or("SOAP header missing")?;
    let ecp_response = header
        .children
        .iter()
        .find(|node| node.attr("AssertionConsumerServiceURL").is_some())
        .ok_or("ecp:Response missing")?;
    let assertion_consumer = ecp_response
        .attr("AssertionConsumerServiceURL")
        .ok_or("AssertionConsumerServiceURL missing")?;
    if assertion_consumer != client.response_consumer_url {
        return Err("assertion consumer does not match responseConsumerURL".into());
    }
    let response = body_element(idp_soap, &document.root, "Response")?;
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
    envelope: &Node,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = child(envelope, "Body").ok_or("SOAP body missing")?;
    let element = body
        .children
        .iter()
        .find(|node| node.local_name == name)
        .ok_or(name)?;
    let slice = xml
        .get(element.start..element.end)
        .ok_or("element offsets")?;
    Ok(slice.to_string())
}

fn child<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|child| child.local_name == name)
}

#[test]
fn enhanced_client_completes_paos_login() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::from_headers(PaosClientRequest::ACCEPT, PaosClientRequest::PAOS_HEADER)?,
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .relay_state(RelayStateParam::try_from_option(Some("state".to_string()))?)
            .provider_name("Example SP")?,
    )?;
    assert_eq!(started.http_response.http_status(), 200);
    assert!(started.http_response.headers().iter().any(
        |header| header.name() == "Content-Type" && header.value() == PaosClientRequest::ACCEPT
    ));
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
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    assert_eq!(answered.http_status(), 200);
    assert!(answered.headers().iter().any(
        |header| header.name() == "Content-Type" && header.value() == "text/xml; charset=utf-8"
    ));

    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let pending = saml_rs::PendingPaosSso::from_snapshot(started.pending.snapshot())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(pending.acs_url(), &EndpointUrl::try_new(SP_ACS)?);
    assert_eq!(answered.session_index(), None);
    Ok(())
}

#[test]
fn paos_response_returns_the_session_index_the_service_provider_accepts(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties_with(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .slo_endpoint(SloEndpoint::redirect("https://idp.example.com/slo")?),
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::from_headers(PaosClientRequest::ACCEPT, PaosClientRequest::PAOS_HEADER)?,
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;

    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let pending = saml_rs::PendingPaosSso::from_snapshot(started.pending.snapshot())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    )?;
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let rejected = idp.reject_paos_sso(
        &sp_descriptor,
        &received,
        Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTH_FAILED)?),
    )?;
    assert!(!rejected.envelope().contains("Assertion>"));
    let sp_request = enhanced_client_takes_response(&client, rejected.envelope())?;
    let error = match sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an error status does not return a session".into()),
    };
    assert!(matches!(error, SamlError::StatusNotSuccess { .. }));
    Ok(())
}

#[test]
fn returned_relay_state_must_match_the_value_the_service_provider_sent(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .relay_state(RelayStateParam::try_from_option(Some("state".to_string()))?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let mut sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    sp_request = sp_request.replace(&relay_state_header("state"), "");
    let error = match sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    ) {
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let error = match idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, "https://idp.example.com/elsewhere")?,
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .acs_url("https://evil.example/acs")?
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
        &PaosAuthnRequest::from_envelope(envelope, IDP_SOAP)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("two SOAP body elements are not one AuthnRequest".into()),
    };
    assert!(matches!(error, SamlError::ProtocolProfile(_)));

    let fault = idp.paos_soap_fault();
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let tampered = idp_request.replace(SP_ACS, "https://evil.example/acs");
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(tampered, IDP_SOAP)?,
        validation(),
    )?;
    let error = match idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an unpublished assertion consumer is rejected".into()),
    };
    assert!(matches!(error, SamlError::Invalid(_)));
    Ok(())
}

#[test]
fn exactly_requested_authn_context_is_checked_and_written() -> Result<(), Box<dyn std::error::Error>>
{
    const SMARTCARD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let requested = idp_request.replace(
        "</samlp:AuthnRequest>",
        &format!("<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"),
    );
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(requested, IDP_SOAP)?,
        validation(),
    )?;
    let unspecified = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    );
    assert!(matches!(unspecified, Err(SamlError::Invalid(_))));

    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default().authn_context(AuthnContextReference::class(SMARTCARD)?),
    )?;
    assert!(answered.envelope().contains(&format!(
        "<saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef>"
    )));
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default().authn_instant(authenticated),
    )?;
    assert!(answered
        .envelope()
        .contains(&format!("AuthnInstant=\"{AUTHENTICATED}\"")));

    let later = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default().authn_instant(SystemTime::now() + Duration::from_secs(3600)),
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let requested = idp_request.replace(
        "<samlp:NameIDPolicy ",
        &format!("<samlp:NameIDPolicy SPNameQualifier=\"{AFFILIATION}\" "),
    );
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(requested, IDP_SOAP)?,
        validation(),
    )?;
    let unqualified = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    );
    assert!(
        matches!(&unqualified, Err(SamlError::Invalid(message)) if message.contains(AFFILIATION)),
        "{unqualified:?}"
    );

    let qualified = Subject::new(
        NameId::with_qualifiers(
            "alice@example.com",
            Some(NameIdFormat::EmailAddress),
            Some(IDP_ENTITY_ID.to_string()),
            Some(AFFILIATION.to_string()),
            None,
        ),
        Vec::new(),
    );
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        qualified,
        RespondPaosSso::default(),
    )?;
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
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
        &PaosAuthnRequest::from_envelope(requested, IDP_SOAP)?,
        validation(),
    )?;
    let other = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        Subject::new(
            NameId::new("bob@example.com", Some(NameIdFormat::EmailAddress)),
            Vec::new(),
        ),
        RespondPaosSso::default(),
    );
    assert!(
        matches!(&other, Err(SamlError::Invalid(message)) if message.contains("requested Subject")),
        "{other:?}"
    );

    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let subject = Subject::new(
        NameId::new(
            "alice@example.com",
            Some(NameIdFormat::Custom("local-format".into())),
        ),
        Vec::new(),
    );
    match idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject,
        RespondPaosSso::default(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("absolute URI reference") => Ok(()),
        Err(error) => Err(format!("unexpected {error:?}").into()),
        Ok(_) => Err("a relative NameID format is not sent".into()),
    }
}

#[test]
fn response_subject_with_caller_supplied_confirmations_is_not_sent(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let subject = Subject::new(
        NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress)),
        vec![SubjectConfirmation::from_raw_xml(
            "<saml:SubjectConfirmation xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Method=\"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key\"/>",
        )],
    );
    match idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject,
        RespondPaosSso::default(),
    ) {
        Err(SamlError::Unsupported(_)) => Ok(()),
        Err(error) => Err(format!("unexpected {error:?}").into()),
        Ok(_) => Err("a caller-supplied SubjectConfirmation is not dropped silently".into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn cbc_encrypted_response_is_signed() -> Result<(), Box<dyn std::error::Error>> {
    let encryption = saml_rs::XmlPolicy {
        encryption: saml_rs::XmlEncryptionPolicy::encrypt_assertions(),
        ..saml_rs::XmlPolicy::default()
    };
    let encrypted_credentials = saml_rs::Credentials {
        encryption_certificate: Some(saml_rs::CertificatePem::new(CERT)),
        decryption_key: Some(saml_rs::PrivateKeyPem::new(PRIVKEY)),
        ..credentials()
    };
    let sp_validation = SpValidationPolicy {
        assertions: saml_rs::AssertionSignaturePolicy::RequireSigned,
        ..SpValidationPolicy::recommended()
    };
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(encrypted_credentials)
            .validation(sp_validation)
            .xml(encryption)
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso/post")?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .xml(encryption)
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    assert!(answered.envelope().contains("EncryptedAssertion"));
    assert!(answered.envelope().contains("<ds:Signature"));
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn relay_state_is_checked_after_the_response_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .relay_state(RelayStateParam::try_from_option(Some("state".to_string()))?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    // Break the response signature without touching the SOAP relay state header.
    let tampered = sp_request.replace("alice@example.com", "mallory@example.com");
    assert_ne!(sp_request, tampered);
    let with_expected_relay = sp
        .finish_paos_sso(
            &idp_descriptor,
            &started.pending,
            &PaosSsoResponse::from_envelope(tampered.clone())?,
            validation(),
        )
        .err()
        .ok_or("a broken response signature does not return a session")?;
    let mut wrong_snapshot = started.pending.snapshot();
    wrong_snapshot.relay_state = RelayStateParam::try_from_option(Some("other".to_string()))?;
    let wrong_pending = saml_rs::PendingPaosSso::from_snapshot(wrong_snapshot)?;
    let with_wrong_relay = sp
        .finish_paos_sso(
            &idp_descriptor,
            &wrong_pending,
            &PaosSsoResponse::from_envelope(tampered)?,
            validation(),
        )
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
fn overlong_relay_state_in_response_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .relay_state(RelayStateParam::try_from_option(Some("state".to_string()))?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let document = parse(answered.envelope())?;
    let response = body_element(answered.envelope(), &document.root, "Response")?;
    let long = "r".repeat(81);
    let sp_request = soap_envelope(&relay_state_header(&long), &response);
    let error = match sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    ) {
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
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
        &PaosAuthnRequest::from_envelope(hoisted, IDP_SOAP)?,
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let declaration = " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"";
    let hoisted = sp_request.replacen(declaration, "", 1).replacen(
        "<SOAP-ENV:Body",
        &format!("<SOAP-ENV:Body{declaration}"),
        1,
    );
    assert_ne!(hoisted, sp_request);
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(hoisted)?,
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn relay_state_xml_forbids_is_rejected_at_start() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _, _, idp_descriptor) = parties()?;
    for relay_state in ["a\u{1}b", "a\u{FFFE}b"] {
        let error = match sp.start_paos_sso(
            &idp_descriptor,
            PaosClientRequest::headers_checked_by_caller(),
            StartPaosSso::to_soap_endpoint(IDP_SOAP)?
                .relay_state(RelayStateParam::try_from_option(Some(
                    relay_state.to_string(),
                ))?)
                .allow_unsigned_authn_request(),
        ) {
            Err(error) => error,
            Ok(_) => return Err("a relay state XML 1.0 forbids is rejected".into()),
        };
        assert!(matches!(error, SamlError::Invalid(_)));
    }
    assert!(StartPaosSso::to_soap_endpoint(IDP_SOAP)?
        .provider_name("a\u{FFFF}b")
        .is_err());
    Ok(())
}

#[test]
fn protocol_binding_naming_paos_is_received() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
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
        &PaosAuthnRequest::from_envelope(with_binding, IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().protocol_binding(), None);
    assert_eq!(
        received
            .message()
            .raw_flow()
            .extract
            .get_str("request.protocolBinding"),
        Some("urn:oasis:names:tc:SAML:2.0:bindings:PAOS")
    );
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    assert_eq!(answered.http_status(), 200);
    Ok(())
}

#[test]
fn protocol_binding_naming_http_artifact_is_not_received() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
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
            &PaosAuthnRequest::from_envelope(with_binding, IDP_SOAP)?,
            validation(),
        ),
        Err(SamlError::UndefinedBinding)
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
    let sp_descriptor =
        SpDescriptor::from_metadata_xml(&metadata, MetadataTrustPolicy::UnsignedForCompatibility)?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
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
            &PaosAuthnRequest::from_envelope(tampered, IDP_SOAP)?,
            validation(),
        )?;
        let error = match idp.respond_paos_sso(
            &sp_descriptor,
            &received,
            subject(),
            RespondPaosSso::default(),
        ) {
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let mail = Attribute::with_name_format(
        "urn:oid:0.9.2342.19200300.100.1.3",
        AttributeNameFormat::Uri,
        vec![AttributeValue::new("alice@example.com")],
    );
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default().attributes(Attributes::new(vec![mail.clone()])),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    )?;
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
    let sp_descriptor =
        SpDescriptor::from_metadata_xml(&metadata, MetadataTrustPolicy::UnsignedForCompatibility)?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let without_selector =
        idp_request.replace(&format!(" AssertionConsumerServiceURL=\"{SP_ACS}\""), "");
    assert_ne!(without_selector, idp_request);
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(without_selector.clone(), IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().acs_url(), None);
    assert_eq!(received.message().acs_index(), None);

    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let rejected = idp.reject_paos_sso(
        &sp_descriptor,
        &received,
        Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTH_FAILED)?),
    )?;
    let sp_request = enhanced_client_takes_response(&client, rejected.envelope())?;
    assert!(matches!(
        sp.finish_paos_sso(
            &idp_descriptor,
            &started.pending,
            &PaosSsoResponse::from_envelope(sp_request)?,
            validation(),
        ),
        Err(SamlError::StatusNotSuccess { .. })
    ));

    let artifact_default = sp_descriptor.metadata_xml().replacen(
        "<AssertionConsumerService ",
        "<AssertionConsumerService index=\"8\" isDefault=\"true\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"https://sp.example.com/acs/artifact\"/><AssertionConsumerService ",
        1,
    );
    let artifact_sp = SpDescriptor::from_metadata_xml(
        &artifact_default,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let received = idp.receive_paos_sso(
        &artifact_sp,
        &PaosAuthnRequest::from_envelope(without_selector, IDP_SOAP)?,
        validation(),
    )?;
    assert!(matches!(
        idp.respond_paos_sso(
            &artifact_sp,
            &received,
            subject(),
            RespondPaosSso::default()
        ),
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let sp_request = enhanced_client_takes_response(&client, answered.envelope())?;
    let outstanding = saml_rs::OutstandingLogout::try_new(
        NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress)),
        Vec::new(),
        saml_rs::SamlInstant::try_new("2999-01-01T00:00:00Z")?,
    )?;
    let error = match sp.finish_paos_sso_with_outstanding_logout(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
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
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let sp_soap = started.http_response.envelope();
    let document = parse(sp_soap)?;
    let authn = body_element(sp_soap, &document.root, "AuthnRequest")?;
    let idp_request = soap_envelope(WSSE_SECURITY_HEADER, &authn);
    let error = match idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an unprocessed mustUnderstand header is refused".into()),
    };
    assert!(matches!(error, SamlError::Xml(_)), "{error:?}");
    Ok(())
}

#[test]
fn service_provider_refuses_a_header_it_must_understand_and_does_not_process(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let document = parse(answered.envelope())?;
    let response = body_element(answered.envelope(), &document.root, "Response")?;
    let sp_request = soap_envelope(WSSE_SECURITY_HEADER, &response);
    let error = match sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(sp_request)?,
        validation(),
    ) {
        Err(error) => error,
        Ok(_) => return Err("an unprocessed mustUnderstand header is refused".into()),
    };
    assert!(matches!(error, SamlError::Xml(_)), "{error:?}");
    Ok(())
}

#[test]
fn service_provider_processes_relay_state_and_paos_response_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?
            .relay_state(RelayStateParam::try_from_option(Some("state".to_string()))?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let document = parse(answered.envelope())?;
    let response = body_element(answered.envelope(), &document.root, "Response")?;
    let paos_response = "<paos:Response xmlns:paos=\"urn:liberty:paos:2003-08\" SOAP-ENV:mustUnderstand=\"1\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/actor/next\"/>";
    let headers = format!("{paos_response}{}", relay_state_header("state"));
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(soap_envelope(&headers, &response))?,
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}
