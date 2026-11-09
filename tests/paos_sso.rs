//! Enhanced Client/Proxy login over PAOS.
//!
//! The enhanced client in this file is the test double for that role. It is
//! not a service-provider or identity-provider facade.

#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::constants::status_code::AUTH_FAILED;
use saml_rs::xml::dom::{parse, Node};
use saml_rs::{
    AcsEndpoint, EndpointUrl, EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    MetadataTrustPolicy, NameId, NameIdFormat, PaosAuthnRequest, PaosClientRequest,
    PaosSsoResponse, RelayStateParam, ReplayPolicy, Saml, SamlError, SamlValidationContext,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartPaosSso, Status, Subject,
    SubordinateStatusCode,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs/post";
const IDP_SOAP: &str = "https://idp.example.com/sso/soap";
const ECP_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

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

fn parties() -> Result<
    (
        Saml<saml_rs::Sp>,
        Saml<saml_rs::Idp>,
        SpDescriptor,
        IdpDescriptor,
    ),
    SamlError,
> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso/post")?)
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let error = match idp.respond_paos_sso(&sp_descriptor, &received, subject()) {
        Err(error) => error,
        Ok(_) => return Err("an unpublished assertion consumer is rejected".into()),
    };
    assert!(matches!(error, SamlError::Invalid(_)));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn cbc_encrypted_response_is_signed() -> Result<(), Box<dyn std::error::Error>> {
    let encryption = saml_rs::XmlPolicy {
        encryption: saml_rs::XmlEncryptionPolicy::encrypt_assertions()
            .with_insecure_software_rsa_key_transport_decryption_allowed(),
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
    assert_eq!(answered.http_status(), 200);
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
        let error = match idp.respond_paos_sso(&sp_descriptor, &received, subject()) {
            Err(error) => error,
            Ok(_) => return Err("an HTTP-Artifact assertion consumer is rejected".into()),
        };
        assert!(matches!(error, SamlError::Invalid(_)));
    }
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
    let answered = idp.respond_paos_sso(&sp_descriptor, &received, subject())?;
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
