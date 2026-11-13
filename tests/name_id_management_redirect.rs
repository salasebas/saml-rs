//! Name identifier management over HTTP-Redirect through the typed
//! identity-provider and service-provider flows.
//!
//! SAML Core §3.6, Profiles §4.5, and Bindings §3.4, as corrected by Approved
//! Errata 05 E8, E12, E14, and E55.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

#[cfg(feature = "crypto-rustcrypto")]
use saml_rs::Credentials;

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use saml_rs::binding::{append_signature, build_redirect_octet};
use saml_rs::constants::{
    name_id_format, signature_algorithm::RSA_SHA256, status_code, ParserType,
};
use saml_rs::crypto::{construct_message_signature, keys::load_private_key};
use saml_rs::error::TimeWindowField;
use saml_rs::{
    AcsEndpoint, BrowserInput, ClockSkew, EndpointUrl, EntityId, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, ManageNameIdRequest, ManageNameIdRequestAgePolicy, ManageNameIdResponse,
    ManageNameIdService, MetadataTrustPolicy, NameId, NameIdChange, NameIdFormat,
    NameIdManagementRefusal, Outbound, Pending, PendingManageNameIdRequest,
    ReceiveNameIdManagement, Received, ReceivedNameIdManagement, ReceivedNameIdManagementRedirect,
    RelayState, RelayStateParam, ReplayCache, ReplayKey, ReplayPolicy, RespondNameIdManagement,
    Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, StartNameIdManagement, Status, SubordinateStatusCode,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_MANAGE: &str = "https://sp.example.com/manage-name-id";
const SP_MANAGE_OTHER: &str = "https://sp.example.com/manage-name-id/other";
const IDP_SSO: &str = "https://idp.example.com/sso";
const IDP_MANAGE: &str = "https://idp.example.com/manage-name-id";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");

fn sp_with(endpoints: &[&str]) -> Result<Saml<saml_rs::Sp>, SamlError> {
    let mut builder = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
        .credentials(signing_credentials())
        .validation(SpValidationPolicy::recommended());
    for endpoint in endpoints {
        builder = builder.manage_name_id_service(ManageNameIdService::redirect(
            EndpointUrl::try_new(*endpoint)?,
        ));
    }
    Saml::sp(builder.build()?)
}

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    sp_with(&[SP_MANAGE])
}

fn idp_with_formats(formats: &[NameIdFormat]) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO)?)
        .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
            IDP_MANAGE,
        )?))
        .credentials(signing_credentials())
        .validation(IdpValidationPolicy::recommended());
    for format in formats {
        builder = builder.name_id_format(format.clone());
    }
    Saml::idp(builder.build()?)
}

fn idp() -> Result<Saml<saml_rs::Idp>, SamlError> {
    idp_with_formats(&[])
}

fn sp_descriptor(sp: &Saml<saml_rs::Sp>) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn idp_descriptor(idp: &Saml<saml_rs::Idp>) -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(Duration::from_secs(300))
}

fn redirect_query<Message>(outbound: &Outbound<Message>) -> Result<String, SamlError> {
    let url = outbound.redirect_url()?;
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(query.to_string())
}

fn request_input(
    outbound: &Outbound<ManageNameIdRequest>,
) -> Result<BrowserInput<ManageNameIdRequest>, SamlError> {
    Ok(BrowserInput::<ManageNameIdRequest>::redirect(
        redirect_query(outbound)?,
    ))
}

fn response_input(
    outbound: &Outbound<ManageNameIdResponse>,
) -> Result<BrowserInput<ManageNameIdResponse>, SamlError> {
    Ok(BrowserInput::<ManageNameIdResponse>::redirect(
        redirect_query(outbound)?,
    ))
}

/// The request a responder is ready to apply.
fn request(
    received: ReceivedNameIdManagementRedirect,
) -> Result<Received<ManageNameIdRequest>, Box<dyn std::error::Error>> {
    match received {
        ReceivedNameIdManagement::Request(request) => Ok(*request),
        ReceivedNameIdManagement::Refused(refused) => {
            Err(format!("request was refused: {:?}", refused.reason()).into())
        }
    }
}

fn alice() -> NameId {
    NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress))
}

/// The SAML message XML carried by an HTTP-Redirect browser action.
fn redirect_message_xml<Message>(
    outbound: &Outbound<Message>,
) -> Result<String, Box<dyn std::error::Error>> {
    let query = redirect_query(outbound)?;
    let encoded = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "SAMLRequest" || name == "SAMLResponse")
        .map(|(_, value)| value.into_owned())
        .ok_or("redirect URL carries no SAML message")?;
    let deflated = saml_rs::binding::base64_decode(&encoded)?;
    Ok(String::from_utf8(saml_rs::binding::deflate_raw_decode(
        &deflated,
    )?)?)
}

/// The pending request, persisted and restored as a deployment would.
fn restored(pending: &PendingManageNameIdRequest) -> Result<PendingManageNameIdRequest, SamlError> {
    Pending::<ManageNameIdRequest>::from_snapshot(pending.snapshot())
}

fn signed_request_input(xml: &str) -> Result<BrowserInput<ManageNameIdRequest>, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let octet = build_redirect_octet(ParserType::ManageNameIdRequest, xml, None, RSA_SHA256)?;
    let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
    let url = append_signature(SP_MANAGE, &octet, &signature);
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(BrowserInput::<ManageNameIdRequest>::redirect(query))
}

fn signed_response_input(xml: &str) -> Result<BrowserInput<ManageNameIdResponse>, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let octet = build_redirect_octet(ParserType::ManageNameIdResponse, xml, None, RSA_SHA256)?;
    let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
    let url = append_signature(IDP_MANAGE, &octet, &signature);
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(BrowserInput::<ManageNameIdResponse>::redirect(query))
}

fn unsigned_response_input(xml: &str) -> Result<BrowserInput<ManageNameIdResponse>, SamlError> {
    let url = saml_rs::binding::build_redirect_url(
        IDP_MANAGE,
        ParserType::ManageNameIdResponse,
        xml,
        None,
    )?;
    let (_, query) = url
        .split_once('?')
        .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
    Ok(BrowserInput::<ManageNameIdResponse>::redirect(query))
}

/// An error `ManageNameIDResponse` from the service provider to the identity
/// provider.
fn sp_error_response_xml(in_response_to: &str) -> String {
    format!(
        concat!(
            r#"<samlp:ManageNameIDResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_answer1" Version="2.0" "#,
            r#"IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}" "#,
            r#"InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>"#,
            r#"</samlp:ManageNameIDResponse>"#,
        ),
        destination = IDP_MANAGE,
        in_response_to = in_response_to,
        issuer = SP_ENTITY_ID,
        status = status_code::REQUESTER,
    )
}

fn idp_request_xml(identifier: &str, change: &str) -> String {
    format!(
        concat!(
            r#"<samlp:ManageNameIDRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_manage1" Version="2.0" "#,
            r#"IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer>{identifier}{change}"#,
            r#"</samlp:ManageNameIDRequest>"#,
        ),
        destination = SP_MANAGE,
        issuer = IDP_ENTITY_ID,
        identifier = identifier,
        change = change,
    )
}

#[derive(Default)]
struct MemoryReplayCache {
    seen: HashMap<String, SystemTime>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

#[test]
fn identity_provider_changes_and_terminates_an_identifier_with_the_service_provider() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    for change in [
        NameIdChange::NewId("alice-2".into()),
        NameIdChange::Terminate,
    ] {
        let relay_state = RelayStateParam::try_from_option(Some("manage"))?;
        let started = idp.start_name_id_management_redirect(
            &sp_peer,
            &alice(),
            &change,
            StartNameIdManagement::redirect().relay_state(relay_state.clone()),
        )?;
        assert!(started.outbound.redirect_url()?.starts_with(SP_MANAGE));

        let request = request(sp.receive_name_id_management_redirect(
            &idp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::redirect(),
            validation(),
        )?)?;
        assert_eq!(request.message().issuer().as_str(), IDP_ENTITY_ID);
        assert_eq!(request.message().name_id(), &alice());
        assert_eq!(request.message().change(), &change);
        assert_eq!(request.relay_state(), &relay_state);

        let response = sp.respond_name_id_management_redirect(
            &idp_peer,
            &request,
            RespondNameIdManagement::redirect(),
        )?;
        assert!(response.redirect_url()?.starts_with(IDP_MANAGE));
        assert_eq!(
            response.relay_state().map(|state| state.as_str()),
            Some("manage")
        );

        let relay_state_received = idp.finish_name_id_management_redirect(
            &sp_peer,
            &restored(&started.pending)?,
            response_input(&response)?,
            validation(),
        )?;
        assert_eq!(relay_state_received, relay_state);
    }
    Ok(())
}

#[test]
fn service_provider_changes_and_terminates_an_identifier_with_the_identity_provider() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    for change in [
        NameIdChange::NewId("alias-42".into()),
        NameIdChange::Terminate,
    ] {
        let started = sp.start_name_id_management_redirect(
            &idp_peer,
            &alice(),
            &change,
            StartNameIdManagement::redirect(),
        )?;
        assert!(started.outbound.redirect_url()?.starts_with(IDP_MANAGE));

        let request = request(idp.receive_name_id_management_redirect(
            &sp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::redirect(),
            validation(),
        )?)?;
        assert_eq!(request.message().issuer().as_str(), SP_ENTITY_ID);
        assert_eq!(request.message().name_id(), &alice());
        assert_eq!(request.message().change(), &change);
        assert_eq!(request.relay_state(), &RelayStateParam::absent());

        let response = idp.respond_name_id_management_redirect(
            &sp_peer,
            &request,
            RespondNameIdManagement::redirect(),
        )?;
        assert!(response.redirect_url()?.starts_with(SP_MANAGE));

        sp.finish_name_id_management_redirect(
            &idp_peer,
            &started.pending,
            response_input(&response)?,
            validation(),
        )?;
    }
    Ok(())
}

#[test]
fn requester_accepts_relay_state_the_responder_adds_to_a_request_without_one() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let key = load_private_key(PRIVKEY, None)?;
    for (added, expected) in [
        ("added", RelayStateParam::try_from_option(Some("added"))?),
        ("", RelayStateParam::PresentEmpty),
    ] {
        let started = sp.start_name_id_management_redirect(
            &idp_peer,
            &alice(),
            &NameIdChange::Terminate,
            StartNameIdManagement::redirect(),
        )?;
        let request = request(idp.receive_name_id_management_redirect(
            &sp_peer,
            request_input(&started.outbound)?,
            ReceiveNameIdManagement::redirect(),
            validation(),
        )?)?;
        let response = idp.respond_name_id_management_redirect(
            &sp_peer,
            &request,
            RespondNameIdManagement::redirect(),
        )?;
        let octet = build_redirect_octet(
            ParserType::ManageNameIdResponse,
            &redirect_message_xml(&response)?,
            Some(added),
            RSA_SHA256,
        )?;
        let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
        let url = append_signature(SP_MANAGE, &octet, &signature);
        let (_, query) = url
            .split_once('?')
            .ok_or("redirect URL is missing a query")?;

        let relay_state = sp.finish_name_id_management_redirect(
            &idp_peer,
            &started.pending,
            BrowserInput::<ManageNameIdResponse>::redirect(query),
            validation(),
        )?;

        assert_eq!(relay_state, expected);
    }
    Ok(())
}

#[test]
fn responder_echoes_a_received_relay_state_up_to_the_receive_limit() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let key = load_private_key(PRIVKEY, None)?;
    let long = "n".repeat(200);
    let started = sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let octet = build_redirect_octet(
        ParserType::ManageNameIdRequest,
        &redirect_message_xml(&started.outbound)?,
        Some(&long),
        RSA_SHA256,
    )?;
    let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
    let url = append_signature(IDP_MANAGE, &octet, &signature);
    let (_, query) = url
        .split_once('?')
        .ok_or("redirect URL is missing a query")?;

    let request = request(idp.receive_name_id_management_redirect(
        &sp_peer,
        BrowserInput::<ManageNameIdRequest>::redirect(query),
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(request.relay_state().as_deref(), Some(long.as_str()));

    let response = idp.respond_name_id_management_redirect(
        &sp_peer,
        &request,
        RespondNameIdManagement::redirect(),
    )?;
    assert_eq!(
        response.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );

    let relay_state = sp.finish_name_id_management_redirect(
        &idp_peer,
        &started.pending,
        response_input(&response)?,
        validation(),
    )?;
    assert_eq!(relay_state.as_deref(), Some(long.as_str()));
    Ok(())
}

#[test]
fn requester_receives_an_error_status_for_an_unknown_principal() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let request = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    let response = sp.respond_name_id_management_redirect(
        &idp_peer,
        &request,
        RespondNameIdManagement::redirect().status(
            Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal()),
        ),
    )?;

    match idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        response_input(&response)?,
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { top, second }) => {
            assert_eq!(top, status_code::REQUESTER);
            assert_eq!(second.as_deref(), Some(status_code::UNKNOWN_PRINCIPAL));
        }
        other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn persistent_identifier_carries_the_qualifiers_core_names() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let persistent = NameId::persistent("pseudonym-1")?;
    let expected = NameId::with_qualifiers(
        "pseudonym-1",
        Some(NameIdFormat::Persistent),
        Some(IDP_ENTITY_ID.into()),
        Some(SP_ENTITY_ID.into()),
        None,
    );

    let from_idp = idp.start_name_id_management_redirect(
        &sp_peer,
        &persistent,
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let received = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&from_idp.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(received.message().name_id(), &expected.clone());

    let from_sp = sp.start_name_id_management_redirect(
        &idp_peer,
        &persistent,
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let received = request(idp.receive_name_id_management_redirect(
        &sp_peer,
        request_input(&from_sp.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(received.message().name_id(), &expected.clone());

    let qualified = NameId::with_qualifiers(
        "pseudonym-1",
        Some(NameIdFormat::Persistent),
        Some("https://other-idp.example.com".into()),
        Some("https://affiliation.example.com".into()),
        Some("alias-7".into()),
    );
    let as_given = sp.start_name_id_management_redirect(
        &idp_peer,
        &qualified,
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let received = request(idp.receive_name_id_management_redirect(
        &sp_peer,
        request_input(&as_given.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(received.message().name_id(), &qualified.clone());
    Ok(())
}

#[test]
fn identity_provider_sends_an_unformatted_identifier_with_its_first_configured_format() -> TestResult
{
    let sp = sp()?;
    let idp = idp_with_formats(&[NameIdFormat::EmailAddress])?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &NameId::new("alice@example.com", None),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let received = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(received.message().name_id(), &alice());
    Ok(())
}

#[test]
fn transient_identifier_is_not_managed() -> TestResult {
    let sp = sp()?;
    let idp = idp_with_formats(&[NameIdFormat::Transient])?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let attempts = [
        idp.start_name_id_management_redirect(
            &sp_peer,
            &NameId::generate_transient(),
            &NameIdChange::Terminate,
            StartNameIdManagement::redirect(),
        ),
        idp.start_name_id_management_redirect(
            &sp_peer,
            &NameId::new("_unformatted", None),
            &NameIdChange::Terminate,
            StartNameIdManagement::redirect(),
        ),
        sp.start_name_id_management_redirect(
            &idp_peer,
            &NameId::generate_transient(),
            &NameIdChange::NewId("alias".into()),
            StartNameIdManagement::redirect(),
        ),
    ];
    for attempt in attempts {
        match attempt {
            Err(SamlError::ProtocolProfile(message)) if message.contains("transient") => {}
            other => return Err(format!("expected transient rejection, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn identity_provider_does_not_send_a_new_persistent_value_longer_than_256_characters() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let sp_peer = sp_descriptor(&sp)?;
    let at_limit = "a".repeat(256);
    idp.start_name_id_management_redirect(
        &sp_peer,
        &NameId::persistent("pseudonym-1")?,
        &NameIdChange::NewId(at_limit.clone()),
        StartNameIdManagement::redirect(),
    )?;
    match idp.start_name_id_management_redirect(
        &sp_peer,
        &NameId::persistent("pseudonym-1")?,
        &NameIdChange::NewId(format!("{at_limit}a")),
        StartNameIdManagement::redirect(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("256") => Ok(()),
        other => Err(format!("expected length rejection, got {other:?}").into()),
    }
}

#[test]
fn unsigned_request_is_rejected() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let query = redirect_query(&started.outbound)?;
    let unsigned: Vec<&str> = query
        .split('&')
        .filter(|pair| !pair.starts_with("SigAlg=") && !pair.starts_with("Signature="))
        .collect();
    match sp.receive_name_id_management_redirect(
        &idp_peer,
        BrowserInput::<ManageNameIdRequest>::redirect(unsigned.join("&")),
        ReceiveNameIdManagement::redirect(),
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!("expected SignatureMissing, got {other:?}").into()),
    }
}

#[test]
fn request_for_another_name_identifier_management_endpoint_is_rejected() -> TestResult {
    let sp = sp_with(&[SP_MANAGE, SP_MANAGE_OTHER])?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let other = validation().with_recipient_endpoint(EndpointUrl::try_new(SP_MANAGE_OTHER)?);
    match sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        other,
    ) {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, SP_MANAGE_OTHER);
            assert_eq!(actual.as_deref(), Some(SP_MANAGE));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn replayed_request_is_rejected() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let mut cache = MemoryReplayCache::default();
    sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation_with_cache(&mut cache),
    )?;
    match sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert!(key.starts_with("manage_name_id_request_id:"));
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

fn issued_at_plus(seconds: i64) -> Result<SystemTime, Box<dyn std::error::Error>> {
    let issued = time::OffsetDateTime::parse(
        "2026-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )?;
    Ok(SystemTime::from(issued + time::Duration::seconds(seconds)))
}

fn one_hour_request_age(now: SystemTime, cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(now, ReplayPolicy::RequireCache(cache))
        .with_clock_skew(ClockSkew::strict())
        .with_replay_retention(Duration::from_secs(300))
        .with_manage_name_id_request_age(ManageNameIdRequestAgePolicy::Bounded {
            max_age: Duration::from_secs(60 * 60),
        })
}

fn assert_request_age_rejected(
    result: Result<ReceivedNameIdManagementRedirect, SamlError>,
) -> TestResult {
    match result {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::ManageNameIdRequestIssueInstant,
        }) => Ok(()),
        other => Err(format!("expected a request age error, got {other:?}").into()),
    }
}

#[test]
fn a_bounded_request_age_rejects_a_request_outside_the_window_before_replay_storage() -> TestResult
{
    let sp = sp()?;
    let idp = idp()?;
    let idp_peer = idp_descriptor(&idp)?;
    let xml = idp_request_xml(
        r#"<saml:NameID>alice@example.com</saml:NameID>"#,
        "<samlp:Terminate/>",
    );
    let other_version = xml.replace(r#"Version="2.0""#, r#"Version="2.1""#);
    let mut cache = MemoryReplayCache::default();

    for (seconds, message) in [
        (60 * 60 + 1, &xml),
        (-1, &xml),
        (60 * 60 + 1, &other_version),
    ] {
        assert_request_age_rejected(sp.receive_name_id_management_redirect(
            &idp_peer,
            signed_request_input(message)?,
            ReceiveNameIdManagement::redirect(),
            one_hour_request_age(issued_at_plus(seconds)?, &mut cache),
        ))?;
    }
    assert!(cache.seen.is_empty());

    for seconds in [0, 60 * 60] {
        let mut cache = MemoryReplayCache::default();
        request(sp.receive_name_id_management_redirect(
            &idp_peer,
            signed_request_input(&xml)?,
            ReceiveNameIdManagement::redirect(),
            one_hour_request_age(issued_at_plus(seconds)?, &mut cache),
        )?)?;
        assert!(cache
            .seen
            .contains_key("manage_name_id_request_id:_manage1"));
    }

    let unbounded = SamlValidationContext::new(
        issued_at_plus(30 * 24 * 60 * 60)?,
        ReplayPolicy::DisabledForCompatibility,
    );
    assert_eq!(
        unbounded.manage_name_id_request_age(),
        ManageNameIdRequestAgePolicy::Disabled
    );
    request(sp.receive_name_id_management_redirect(
        &idp_peer,
        signed_request_input(&xml)?,
        ReceiveNameIdManagement::redirect(),
        unbounded,
    )?)?;
    Ok(())
}

#[test]
fn identifiers_that_do_not_decrypt_are_answered_with_an_error_status() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let idp_peer = idp_descriptor(&idp)?;
    let name_id = r#"<saml:NameID>alice@example.com</saml:NameID>"#;
    let encrypted_id = r#"<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedID>"#;
    let new_encrypted_id = r#"<samlp:NewEncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></samlp:NewEncryptedID>"#;
    for (identifier, change, reason, status) in [
        (
            encrypted_id,
            "<samlp:Terminate/>",
            NameIdManagementRefusal::UndecryptableIdentifier,
            format!(
                r#"<samlp:StatusCode Value="{}"><samlp:StatusCode Value="{}"/></samlp:StatusCode>"#,
                status_code::REQUESTER,
                status_code::UNKNOWN_PRINCIPAL
            ),
        ),
        (
            name_id,
            new_encrypted_id,
            NameIdManagementRefusal::UndecryptableNewIdentifier,
            format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::REQUESTER),
        ),
    ] {
        let input = signed_request_input(&idp_request_xml(identifier, change))?;
        let ReceivedNameIdManagement::Refused(refused) = sp.receive_name_id_management_redirect(
            &idp_peer,
            input,
            ReceiveNameIdManagement::redirect(),
            validation(),
        )?
        else {
            return Err("an undecryptable identifier was not refused".into());
        };
        assert_eq!(refused.reason(), reason);
        assert!(refused.response().redirect_url()?.starts_with(IDP_MANAGE));
        let xml = redirect_message_xml(refused.response())?;
        assert!(xml.contains(r#"InResponseTo="_manage1""#));
        assert!(xml.contains(&format!("<samlp:Status>{status}</samlp:Status>")));
    }
    Ok(())
}

#[test]
fn request_must_name_one_identifier_and_one_change() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let idp_peer = idp_descriptor(&idp)?;
    let name_id = r#"<saml:NameID>alice@example.com</saml:NameID>"#;
    for (identifier, change) in [
        ("", "<samlp:Terminate/>"),
        (name_id, ""),
        (name_id, "<samlp:NewID>a</samlp:NewID><samlp:Terminate/>"),
    ] {
        let input = signed_request_input(&idp_request_xml(identifier, change))?;
        match sp.receive_name_id_management_redirect(
            &idp_peer,
            input,
            ReceiveNameIdManagement::redirect(),
            validation(),
        ) {
            Err(SamlError::ProtocolProfile(message)) if message.contains("requires one NameID") => {
            }
            other => return Err(format!("expected a choice error, got {other:?}").into()),
        }
    }
    for (identifier, change) in [
        (
            name_id,
            r#"<samlp:NewID><ext:Value xmlns:ext="urn:test">alias</ext:Value></samlp:NewID>"#,
        ),
        (name_id, "<samlp:Terminate>now</samlp:Terminate>"),
        (
            r#"<saml:NameID><ext:Value xmlns:ext="urn:test">alice</ext:Value></saml:NameID>"#,
            "<samlp:Terminate/>",
        ),
    ] {
        let input = signed_request_input(&idp_request_xml(identifier, change))?;
        let received = sp.receive_name_id_management_redirect(
            &idp_peer,
            input,
            ReceiveNameIdManagement::redirect(),
            validation(),
        );
        assert!(
            matches!(
                received,
                Err(SamlError::ProtocolProfile(_) | SamlError::Xml(_))
            ),
            "{change} was accepted: {received:?}"
        );
    }
    let input = signed_request_input(&idp_request_xml(
        name_id,
        "<samlp:NewID>alice-2</samlp:NewID>",
    ))?;
    let request = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        input,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(
        request.message().change(),
        &NameIdChange::NewId("alice-2".into())
    );
    Ok(())
}

#[test]
fn http_name_identifier_management_endpoint_needs_an_explicit_relaxation() -> TestResult {
    const HTTP_SP_METADATA: &str = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sp.example.com/manage-name-id"/><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/></SPSSODescriptor></EntityDescriptor>"#;
    let idp = idp()?;
    let sp_peer = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        HTTP_SP_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    match idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => return Err(format!("expected an https rejection, got {other:?}").into()),
    }
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect().allow_http_name_id_management(),
    )?;
    assert!(started
        .outbound
        .redirect_url()?
        .starts_with("http://sp.example.com/manage-name-id?"));
    Ok(())
}

#[test]
fn peer_without_a_name_identifier_management_endpoint_is_missing_metadata() -> TestResult {
    let sp = sp_with(&[])?;
    let idp = idp()?;
    match idp.start_name_id_management_redirect(
        &sp_descriptor(&sp)?,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    ) {
        Err(SamlError::MissingMetadata(element)) if element == "ManageNameIDService" => Ok(()),
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[test]
fn generated_request_names_the_identifier_and_one_change() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let sp_peer = sp_descriptor(&sp)?;
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::NewId("alice-2".into()),
        StartNameIdManagement::redirect(),
    )?;
    let query = redirect_query(&started.outbound)?;
    let encoded = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("SAMLRequest="))
        .ok_or("missing SAMLRequest")?;
    let decoded = url::form_urlencoded::parse(format!("v={encoded}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .ok_or("undecodable SAMLRequest")?;
    let xml = String::from_utf8(saml_rs::binding::deflate_raw_decode(
        &saml_rs::binding::base64_decode(&decoded)?,
    )?)?;
    assert!(xml.contains(&format!(
        r#"<saml:NameID Format="{}">alice@example.com</saml:NameID><samlp:NewID>alice-2</samlp:NewID>"#,
        name_id_format::EMAIL_ADDRESS
    )));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(!xml.contains("Terminate"));
    Ok(())
}

#[test]
fn error_status_is_reported_only_for_an_authenticated_matching_response() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let sp_peer = sp_descriptor(&sp)?;
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let request_id = started.pending.id().as_str();

    let unsigned = unsigned_response_input(&sp_error_response_xml(request_id))?;
    match idp.finish_name_id_management_redirect(&sp_peer, &started.pending, unsigned, validation())
    {
        Err(SamlError::SignatureMissing) => {}
        other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
    }

    let other_request = signed_response_input(&sp_error_response_xml("_another_request"))?;
    match idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        other_request,
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { .. }) => {}
        other => return Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }

    let matching = signed_response_input(&sp_error_response_xml(request_id))?;
    match idp.finish_name_id_management_redirect(&sp_peer, &started.pending, matching, validation())
    {
        Err(SamlError::StatusNotSuccess { top, .. }) if top == status_code::REQUESTER => Ok(()),
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}

#[test]
fn request_goes_to_the_service_provider_role_of_a_dual_role_peer() -> TestResult {
    let dual_role = format!(
        concat!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">"#,
            r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/as-idp/manage-name-id"/>"#,
            r#"<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/as-idp/sso"/>"#,
            r#"</IDPSSODescriptor>"#,
            r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{manage}"/>"#,
            r#"<AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}"/>"#,
            r#"</SPSSODescriptor></EntityDescriptor>"#,
        ),
        entity = SP_ENTITY_ID,
        manage = SP_MANAGE,
        acs = SP_ACS,
    );
    let sp_peer = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &dual_role,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = idp()?.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    assert!(started
        .outbound
        .redirect_url()?
        .starts_with(&format!("{SP_MANAGE}?")));
    Ok(())
}

#[test]
fn a_provider_without_its_own_endpoint_neither_sends_nor_accepts() -> TestResult {
    let lite_sp = sp_with(&[])?;
    let sp = sp()?;
    let idp = idp()?;
    let (sp_peer, idp_peer) = (sp_descriptor(&sp)?, idp_descriptor(&idp)?);

    let started = lite_sp.start_name_id_management_redirect(
        &idp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    );
    assert!(
        matches!(started, Err(SamlError::MissingMetadata(element)) if element == "ManageNameIDService")
    );

    let from_idp = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let received = lite_sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&from_idp.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    );
    assert!(
        matches!(received, Err(SamlError::MissingMetadata(element)) if element == "ManageNameIDService")
    );
    Ok(())
}

#[test]
fn a_service_provider_does_not_publish_a_soap_endpoint() -> TestResult {
    let config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(SP_MANAGE)?))
        .credentials(signing_credentials())
        .validation(SpValidationPolicy::recommended())
        .build();

    assert!(matches!(config, Err(SamlError::Unsupported(_))));
    Ok(())
}

#[test]
fn metadata_publishes_each_endpoint_in_the_schema_order() -> TestResult {
    let sp = sp()?;
    let sp_metadata = sp.metadata_xml();
    let sp_positions = [
        "<KeyDescriptor",
        "<ManageNameIDService",
        "<NameIDFormat",
        "<AssertionConsumerService",
    ]
    .map(|element| sp_metadata.find(element));
    assert!(sp_metadata.contains(&format!(
        r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{SP_MANAGE}"/>"#
    )));
    assert!(sp_positions.iter().all(Option::is_some));
    assert!(sp_positions.is_sorted());

    let both = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO)?)
            .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
                "https://idp.example.com/manage-name-id/soap",
            )?))
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                IDP_MANAGE,
            )?))
            .credentials(signing_credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp_metadata = both.metadata_xml();
    assert!(idp_metadata.contains(
        r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/manage-name-id/soap"/>"#
    ));
    assert!(idp_metadata.contains(&format!(
        r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_MANAGE}"/>"#
    )));

    let sp_peer = sp_descriptor(&sp)?;
    let started = both.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let request = request(sp.receive_name_id_management_redirect(
        &idp_descriptor(&both)?,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    let response = sp.respond_name_id_management_redirect(
        &idp_descriptor(&both)?,
        &request,
        RespondNameIdManagement::redirect(),
    )?;
    assert!(response.redirect_url()?.starts_with(IDP_MANAGE));
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn hmac_sha1_signed_messages_verify_with_the_peer_secret() -> TestResult {
    use saml_rs::{AlgorithmPolicy, HmacSecret, SignatureAlgorithm};

    let hmac = |secret: &[u8]| -> Result<(AlgorithmPolicy, Credentials), SamlError> {
        Ok((
            AlgorithmPolicy {
                signature: SignatureAlgorithm::HmacSha1,
                ..AlgorithmPolicy::default()
            },
            Credentials {
                hmac_secret: Some(HmacSecret::try_new(secret)?),
                ..Credentials::default()
            },
        ))
    };
    let (sp_algorithms, sp_credentials) = hmac(b"service-provider-hmac-secret")?;
    let (idp_algorithms, idp_credentials) = hmac(b"identity-provider-hmac-secret")?;
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                SP_MANAGE,
            )?))
            .credentials(sp_credentials)
            .algorithms(sp_algorithms)
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO)?)
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                IDP_MANAGE,
            )?))
            .credentials(idp_credentials)
            .algorithms(idp_algorithms)
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_peer =
        sp_descriptor(&sp)?.with_hmac_secret(HmacSecret::try_new(b"service-provider-hmac-secret")?);
    let idp_peer = idp_descriptor(&idp)?
        .with_hmac_secret(HmacSecret::try_new(b"identity-provider-hmac-secret")?);

    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let request = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        request_input(&started.outbound)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    let response = sp.respond_name_id_management_redirect(
        &idp_peer,
        &request,
        RespondNameIdManagement::redirect(),
    )?;
    idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        response_input(&response)?,
        validation(),
    )?;
    Ok(())
}

#[test]
fn a_response_with_two_statuses_is_rejected() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let sp_peer = sp_descriptor(&sp)?;
    let started = idp.start_name_id_management_redirect(
        &sp_peer,
        &alice(),
        &NameIdChange::Terminate,
        StartNameIdManagement::redirect(),
    )?;
    let xml = format!(
        concat!(
            r#"<samlp:ManageNameIDResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_answer2" Version="2.0" "#,
            r#"IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}" "#,
            r#"InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="{success}"/></samlp:Status>"#,
            r#"<samlp:Status><samlp:StatusCode Value="{requester}"/></samlp:Status>"#,
            r#"</samlp:ManageNameIDResponse>"#,
        ),
        destination = IDP_MANAGE,
        in_response_to = started.pending.id().as_str(),
        issuer = SP_ENTITY_ID,
        success = status_code::SUCCESS,
        requester = status_code::REQUESTER,
    );

    let finished = idp.finish_name_id_management_redirect(
        &sp_peer,
        &started.pending,
        signed_response_input(&xml)?,
        validation(),
    );

    assert!(
        matches!(
            finished,
            Err(SamlError::ProtocolProfile(_) | SamlError::Xml(_))
        ),
        "two statuses were accepted: {finished:?}"
    );
    Ok(())
}

#[test]
fn a_version_other_than_2_0_is_answered_with_version_mismatch() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let idp_peer = idp_descriptor(&idp)?;
    let xml = idp_request_xml(
        r#"<saml:NameID>alice@example.com</saml:NameID>"#,
        "<samlp:Terminate/>",
    )
    .replace(r#"Version="2.0""#, r#"Version="2.1""#);

    let ReceivedNameIdManagement::Refused(refused) = sp.receive_name_id_management_redirect(
        &idp_peer,
        signed_request_input(&xml)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?
    else {
        return Err("a version mismatch was not refused".into());
    };

    assert_eq!(refused.reason(), NameIdManagementRefusal::VersionMismatch);
    let answer = redirect_message_xml(refused.response())?;
    assert!(answer.contains(&format!(
        r#"<samlp:StatusCode Value="{}"/>"#,
        status_code::VERSION_MISMATCH
    )));

    let declared = idp_request_xml(
        r#"<saml:NameID>alice@example.com</saml:NameID>"#,
        "<samlp:Terminate/>",
    )
    .replace(
        r#"Version="2.0""#,
        r#"xmlns:Version="urn:unused" Version="2.0""#,
    );
    let request = request(sp.receive_name_id_management_redirect(
        &idp_peer,
        signed_request_input(&declared)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;
    assert_eq!(request.message().change(), &NameIdChange::Terminate);
    Ok(())
}

#[test]
fn a_request_is_read_under_the_configured_xml_limits() -> TestResult {
    let limits = saml_rs::xml::XmlLimits {
        max_attributes_per_element: 128,
        ..saml_rs::xml::XmlLimits::default()
    };
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
                SP_MANAGE,
            )?))
            .credentials(signing_credentials())
            .xml(saml_rs::XmlPolicy {
                limits,
                ..saml_rs::XmlPolicy::default()
            })
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = idp()?;
    let attributes: String = (0..65).map(|index| format!(r#" a{index}="v""#)).collect();
    let extensions = format!(
        r#"<samlp:Extensions><ext:Data xmlns:ext="urn:test"{attributes}/></samlp:Extensions>"#
    );
    let xml = idp_request_xml(
        &format!("{extensions}<saml:NameID>alice@example.com</saml:NameID>"),
        "<samlp:Terminate/>",
    );

    let request = request(sp.receive_name_id_management_redirect(
        &idp_descriptor(&idp)?,
        signed_request_input(&xml)?,
        ReceiveNameIdManagement::redirect(),
        validation(),
    )?)?;

    assert_eq!(request.message().change(), &NameIdChange::Terminate);
    Ok(())
}

#[test]
fn a_request_out_of_schema_order_or_with_an_extra_element_is_rejected() -> TestResult {
    let sp = sp()?;
    let idp = idp()?;
    let idp_peer = idp_descriptor(&idp)?;
    let name_id = r#"<saml:NameID>alice@example.com</saml:NameID>"#;
    for (identifier, change) in [
        ("<samlp:Terminate/>", name_id),
        (
            name_id,
            r#"<samlp:Terminate/><samlp:Extra xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
        ),
    ] {
        let input = signed_request_input(&idp_request_xml(identifier, change))?;
        let received = sp.receive_name_id_management_redirect(
            &idp_peer,
            input,
            ReceiveNameIdManagement::redirect(),
            validation(),
        );
        assert!(
            matches!(
                received,
                Err(SamlError::ProtocolProfile(_) | SamlError::Xml(_))
            ),
            "{identifier}{change} was accepted: {received:?}"
        );
    }
    Ok(())
}
