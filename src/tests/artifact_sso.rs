//! Web Browser SSO with the `<Response>` delivered as an HTTP-Artifact,
//! through the typed identity provider and service provider.
//!
//! The identity provider stores the response and hands the browser an
//! artifact. The service provider reads the artifact at its assertion
//! consumer, resolves it over SOAP, and establishes the session. The
//! deployment still performs HTTP and TLS.
#![cfg(crypto)]

use super::common;

use common::signing_credentials;

use std::time::{Duration, SystemTime};

use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::transform_algorithm;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::error::SubjectConfirmationReason;
use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, ArtifactDelivery, ArtifactRelease, ArtifactResolutionService,
    ArtifactWithheld, AuthnRequest, DeliveredArtifact, EndpointUrl, EntityId, FormField,
    IdentityProvider, IdpConfig, IdpConfigBuilder, IdpDescriptor, Inbound, IssuedArtifacts,
    MessageConfidentiality, MessageIntegrity, MetadataTrustPolicy, NameId, NameIdFormat, Outbound,
    PartyAuthentication, PendingAuthnRequest, Received, RelayState, ReplayPolicy,
    ResolvedProtocolMessage, RespondSso, SamlError, SamlValidationContext, ServiceProvider,
    SoapChannel, SoapResponse, SpConfig, SpConfigBuilder, SpDescriptor, SsoAssertion, SsoEndpoint,
    SsoOutcome, SsoResponse, SsoResponseBinding, SsoSession, StartSso, Status, StatusMessage,
    SubordinateStatusCode, TransformAlgorithm, MAX_RECEIVED_RELAY_STATE_BYTES,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{
    AssertionEncryptionPolicy, CertificatePem, PrivateKeyPem, SloEndpoint, XmlEncryptionPolicy,
    XmlPolicy,
};
use url::Url;

mod soap_signatures;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_ARTIFACT: &str = "https://sp.example.com/acs/artifact";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const RESOLUTION_URL: &str = "https://idp.example.com/artifact";
const ARTIFACT_LIFETIME: Duration = Duration::from_secs(60);
const USER: &str = "user@example.com";
const AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

struct Parties {
    idp: IdentityProvider,
    sp: ServiceProvider,
    idp_metadata: IdpDescriptor,
    sp_metadata: SpDescriptor,
}

fn parties() -> Result<Parties, SamlError> {
    parties_with_idp_algorithms(AlgorithmPolicy::default())
}

fn parties_with_idp_algorithms(algorithms: AlgorithmPolicy) -> Result<Parties, SamlError> {
    parties_with_consumers(
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
        AcsEndpoint::artifact(SP_ACS_ARTIFACT)?,
        algorithms,
    )
}

/// Parties whose service provider marks the HTTP-Artifact consumer default,
/// so an unsolicited artifact response can be sent to it.
fn unsolicited_parties() -> Result<Parties, SamlError> {
    parties_with_consumers(
        AcsEndpoint::post(SP_ACS_POST)?,
        AcsEndpoint::artifact(SP_ACS_ARTIFACT)?.with_default(),
        AlgorithmPolicy::default(),
    )
}

fn parties_with_consumers(
    post: AcsEndpoint,
    artifact: AcsEndpoint,
    algorithms: AlgorithmPolicy,
) -> Result<Parties, SamlError> {
    let (idp, sp) = artifact_config_builders(post, artifact)?;
    build_parties(
        idp.credentials(signing_credentials())
            .algorithms(algorithms),
        sp.credentials(signing_credentials()),
    )
}

fn artifact_config_builders(
    post: AcsEndpoint,
    artifact: AcsEndpoint,
) -> Result<(IdpConfigBuilder, SpConfigBuilder), SamlError> {
    Ok((
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect(IDP_SSO_REDIRECT)?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new(RESOLUTION_URL)?,
        )),
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, post).acs_endpoint(artifact),
    ))
}

fn build_parties(idp: IdpConfigBuilder, sp: SpConfigBuilder) -> Result<Parties, SamlError> {
    let idp = IdentityProvider::new(idp.build()?);
    let sp = ServiceProvider::new(sp.build()?);
    let idp_metadata = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let sp_metadata = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok(Parties {
        idp,
        sp,
        idp_metadata,
        sp_metadata,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn principal() -> NameId {
    NameId::new(USER).with_format(NameIdFormat::EmailAddress)
}

fn confidential() -> SoapChannel {
    SoapChannel::mutually_authenticated_confidential()
}

/// The service provider asks for an artifact response, and the identity
/// provider receives that request.
fn requested(
    parties: &Parties,
    relay_state: Option<RelayState>,
) -> Result<(PendingAuthnRequest, Received<AuthnRequest>), Box<dyn std::error::Error>> {
    let options = StartSso::redirect().response_binding(SsoResponseBinding::Artifact);
    let options = match relay_state {
        Some(relay_state) => options.relay_state(relay_state),
        None => options,
    };
    let started = parties.sp.start_sso(&parties.idp_metadata, options)?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let request = parties.idp.receive_sso(
        &parties.sp_metadata,
        Inbound::redirect(url.query().ok_or("missing query")?),
        validation(),
    )?;
    Ok((started.pending, request))
}

/// The browser follows the redirect, and the service provider resolves the
/// artifact it received and finishes the login.
fn follow_redirect_and_finish(
    parties: &Parties,
    pending: &PendingAuthnRequest,
    response: &Outbound<SsoResponse>,
    issued: &mut IssuedArtifacts,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    resolve_and_finish(parties, pending, delivered_by(response)?, issued)
}

/// The artifact the browser carries to the assertion consumer in a redirect.
fn delivered_by(
    response: &Outbound<SsoResponse>,
) -> Result<DeliveredArtifact, Box<dyn std::error::Error>> {
    let url = Url::parse(response.redirect_url()?)?;
    Ok(DeliveredArtifact::from_query(
        url.query().ok_or("missing query")?,
    )?)
}

#[test]
fn a_response_delivered_as_an_artifact_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, request) = requested(&parties, None)?;
    assert_eq!(pending.acs().binding(), SsoResponseBinding::Artifact);
    assert_eq!(pending.acs().location().as_str(), SP_ACS_ARTIFACT);

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let mismatched = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(NameId::new(USER)),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    );
    assert!(matches!(
        mismatched,
        Err(SamlError::NameIdPolicyFormatMismatch {
            requested: NameIdFormat::EmailAddress,
            issued: None,
            ..
        })
    ));
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;

    let url = Url::parse(response.redirect_url()?)?;
    assert_eq!(
        format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().ok_or("missing host")?,
            url.path()
        ),
        SP_ACS_ARTIFACT
    );
    let names: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert_eq!(names, ["SAMLart"]);

    let session = follow_redirect_and_finish(&parties, &pending, &response, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn an_artifact_response_keeps_exclusive_canonicalization_inside_soap(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with_idp_algorithms(AlgorithmPolicy {
        signed_reference_transforms: vec![
            TransformAlgorithm::EnvelopedSignature,
            TransformAlgorithm::CanonicalXml,
        ],
        ..AlgorithmPolicy::default()
    })?;
    let (pending, request) = requested(&parties, None)?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        delivered.artifact(),
        confidential(),
        validation(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        confidential(),
    )?;

    let envelope = answer.response().envelope();
    assert!(envelope.contains(transform_algorithm::EXC_C14N));
    assert!(!envelope.contains(transform_algorithm::C14N));
    let resolved = resolution.finish(envelope)?;
    let session = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn relay_state_travels_with_the_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let relay_state = RelayState::try_new("state & more=1")?;
    let (pending, request) = requested(&parties, Some(relay_state.clone()))?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;

    let url = Url::parse(response.redirect_url()?)?;
    let delivered = DeliveredArtifact::from_query(url.query().ok_or("missing query")?)?;
    assert_eq!(delivered.relay_state(), Some(&relay_state));

    let session = follow_redirect_and_finish(&parties, &pending, &response, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_artifact_redirect_keeps_the_consumer_fragment_after_the_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with_consumers(
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
        AcsEndpoint::artifact(format!("{SP_ACS_ARTIFACT}#done"))?,
        AlgorithmPolicy::default(),
    )?;
    let (_, request) = requested(&parties, None)?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;

    let url = Url::parse(response.redirect_url()?)?;
    assert_eq!(url.fragment(), Some("done"));
    let names: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert_eq!(names, ["SAMLart"]);
    Ok(())
}

#[test]
fn a_relay_state_the_service_provider_did_not_send_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, request) = requested(&parties, Some(RelayState::try_new("expected")?))?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let url = Url::parse(response.redirect_url()?)?;
    let swapped: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(url.query_pairs().map(|(name, value)| {
            let value = if name == "RelayState" {
                "swapped".into()
            } else {
                value
            };
            (name, value)
        }))
        .finish();
    let delivered = DeliveredArtifact::from_query(&swapped)?;

    let result = resolve_and_finish(&parties, &pending, delivered, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::RelayStateMismatch { .. })
    ));
    Ok(())
}

#[test]
fn a_received_relay_state_up_to_the_receive_limit_travels_with_the_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let long = "r".repeat(200);
    let started = parties.sp.start_sso(
        &parties.idp_metadata,
        StartSso::redirect().response_binding(SsoResponseBinding::Artifact),
    )?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let query = format!("{}&RelayState={long}", url.query().ok_or("missing query")?);
    let request =
        parties
            .idp
            .receive_sso(&parties.sp_metadata, Inbound::redirect(query), validation())?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    assert_eq!(
        delivered.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );

    let session = resolve_and_finish(&parties, &started.pending, delivered, &mut issued)?;
    assert_eq!(
        session.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );
    Ok(())
}

#[test]
fn a_relay_state_above_the_receive_limit_is_not_delivered() -> Result<(), Box<dyn std::error::Error>>
{
    let query = |relay_state: String| {
        format!(
            "SAMLart=AAQAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D&RelayState={relay_state}"
        )
    };
    let longest = "r".repeat(MAX_RECEIVED_RELAY_STATE_BYTES);
    let delivered = DeliveredArtifact::from_query(&query(longest.clone()))?;
    assert_eq!(
        delivered.relay_state().map(RelayState::as_str),
        Some(longest.as_str())
    );
    assert!(matches!(
        DeliveredArtifact::from_query(&query("r".repeat(MAX_RECEIVED_RELAY_STATE_BYTES + 1))),
        Err(SamlError::LimitExceeded {
            limit: saml_rs::ResourceLimit::RelayStateBytes,
            maximum: MAX_RECEIVED_RELAY_STATE_BYTES,
        })
    ));
    Ok(())
}

/// The service provider resolves `delivered` and finishes the login.
fn resolve_and_finish(
    parties: &Parties,
    pending: &PendingAuthnRequest,
    delivered: DeliveredArtifact,
    issued: &mut IssuedArtifacts,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let resolved = resolve(parties, &delivered, issued)?;
    Ok(parties.sp.finish_sso(
        &parties.idp_metadata,
        pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?)
}

fn resolve(
    parties: &Parties,
    delivered: &DeliveredArtifact,
    issued: &mut IssuedArtifacts,
) -> Result<ResolvedProtocolMessage, Box<dyn std::error::Error>> {
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        delivered.artifact(),
        confidential(),
        validation(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        issued,
        confidential(),
    )?;
    Ok(resolution.finish(answer.response().envelope())?)
}

fn saml_error(result: Result<SsoSession, Box<dyn std::error::Error>>) -> Option<SamlError> {
    result
        .err()
        .and_then(|err| err.downcast::<SamlError>().ok())
        .map(|err| *err)
}

#[test]
fn an_artifact_delivered_in_a_form_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let relay_state = RelayState::try_new("form-state")?;
    let (pending, request) = requested(&parties, Some(relay_state))?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::post_form(0)),
        &mut issued,
    )?;

    let form = response.post_form()?;
    assert_eq!(form.action().as_str(), SP_ACS_ARTIFACT);
    let names: Vec<&str> = form.fields().iter().map(FormField::name).collect();
    assert_eq!(names, ["SAMLart", "RelayState"]);
    assert_eq!(form.value("RelayState"), Some("form-state"));
    assert!(matches!(
        response.redirect_url(),
        Err(SamlError::OutboundDeliveryMismatch {
            actual: saml_rs::constants::Binding::Post
        })
    ));

    let delivered = DeliveredArtifact::from_form(form.fields())?;
    let session = resolve_and_finish(&parties, &pending, delivered, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_error_response_is_resolved_the_same_way_and_establishes_no_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, request) = requested(&parties, None)?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let status =
        Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTHN_FAILED)?);
    let diagnostic = " Passkey <required> & unavailable\r\nTry again. ";
    for expected_diagnostic in [None, Some(diagnostic)] {
        let options = RespondSso::artifact(ArtifactDelivery::redirect(0));
        let options = match expected_diagnostic {
            Some(diagnostic) => options.status_message(diagnostic),
            None => options,
        };
        let response = parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            SsoOutcome::Failure(status.clone()),
            options,
            &mut issued,
        )?;

        let delivered = delivered_by(&response)?;
        let resolved = resolve(&parties, &delivered, &mut issued)?;
        assert_eq!(resolved.local_name(), "Response");
        assert!(!resolved.xml().contains("Assertion"));

        match parties.sp.finish_sso(
            &parties.idp_metadata,
            &pending,
            Inbound::artifact(delivered, resolved),
            validation(),
        ) {
            Err(SamlError::StatusNotSuccess {
                status: received,
                status_message,
            }) => {
                assert_eq!(received, status);
                assert_eq!(
                    status_message.as_ref().map(StatusMessage::as_str),
                    expected_diagnostic
                );
            }
            other => return Err(format!("expected a status error, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn artifact_error_exposes_only_diagnostic_signed_by_inner_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, _) = requested(&parties, None)?;
    let diagnostic = "MFA provider unavailable";
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_artifact_error" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" InResponseTo="{}">
        <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
                <samlp:StatusCode Value="{AUTHN_FAILED}"/>
            </samlp:StatusCode>
            <samlp:StatusMessage>{diagnostic}</samlp:StatusMessage>
        </samlp:Status>
        </samlp:Response>"#,
        pending.request_id().as_str()
    );
    let signed_inner = sign_response(&xml)?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    for (payload, sign_outer, expected) in [
        (&signed_inner, false, Some(diagnostic)),
        (&xml, false, None),
        (&xml, true, None),
    ] {
        let artifact = parties
            .idp
            .issue_artifact(&parties.sp_metadata, payload, 0, &mut issued)?;
        let delivered =
            DeliveredArtifact::from_form(&[FormField::new("SAMLart", artifact.as_str())])?;
        let resolution = parties.sp.resolve_artifact(
            &parties.idp_metadata,
            delivered.artifact(),
            confidential(),
            validation(),
        )?;
        let answer = parties.idp.answer_artifact_resolve(
            &parties.sp_metadata,
            resolution.request().envelope(),
            &mut issued,
            confidential(),
        )?;
        let envelope = answer.response().envelope();
        let resolved = if sign_outer {
            let doc = roxmltree::Document::parse(envelope)?;
            let outer = doc
                .descendants()
                .find(|node| {
                    node.has_tag_name((saml_rs::constants::namespace::PROTOCOL, "ArtifactResponse"))
                })
                .ok_or("missing ArtifactResponse")?;
            let signed = sign_response(&envelope[outer.range()])?;
            resolution.finish(SoapResponse::try_new(&signed)?.envelope())?
        } else {
            resolution.finish(envelope)?
        };
        let result = parties.sp.finish_sso(
            &parties.idp_metadata,
            &pending,
            Inbound::artifact(delivered, resolved),
            validation(),
        );
        let Err(SamlError::StatusNotSuccess {
            status,
            status_message,
        }) = result
        else {
            return Err(format!("expected StatusNotSuccess, got {result:?}").into());
        };
        assert_eq!(
            status,
            Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTHN_FAILED)?)
        );
        assert_eq!(status_message.as_ref().map(StatusMessage::as_str), expected);
    }
    Ok(())
}

#[test]
fn an_unsolicited_artifact_response_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = unsolicited_parties()?;
    let relay_state = RelayState::try_new("https://sp.example.com/app")?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.initiate_sso_artifact(
        &parties.sp_metadata,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)).relay_state(relay_state.clone()),
        &mut issued,
    )?;
    assert!(response.redirect_url()?.starts_with(SP_ACS_ARTIFACT));

    let delivered = delivered_by(&response)?;
    assert_eq!(delivered.relay_state(), Some(&relay_state));
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    let session = parties.sp.accept_unsolicited_sso(
        &parties.idp_metadata,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn a_request_for_an_artifact_response_is_not_answered_over_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (_pending, request) = requested(&parties, None)?;
    assert_eq!(
        request.message().protocol_binding(),
        Some(SsoResponseBinding::Artifact)
    );
    assert!(matches!(
        parties.idp.respond_sso(
            &parties.sp_metadata,
            &request,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn a_missing_resolution_service_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (_pending, request) = requested(&parties, None)?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    assert!(matches!(
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            SsoAssertion::new(principal()),
            RespondSso::artifact(ArtifactDelivery::redirect(7)),
            &mut issued
        ),
        Err(SamlError::MissingMetadata(_))
    ));
    Ok(())
}

#[test]
fn a_message_resolved_from_another_artifact_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let (pending, request) = requested(&parties, None)?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let respond = |issued: &mut IssuedArtifacts| {
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            SsoAssertion::new(principal()),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            issued,
        )
    };
    let first = delivered_by(&respond(&mut issued)?)?;
    let second = delivered_by(&respond(&mut issued)?)?;
    let resolved_second = resolve(&parties, &second, &mut issued)?;

    assert!(matches!(
        parties.sp.finish_sso(
            &parties.idp_metadata,
            &pending,
            Inbound::artifact(first, resolved_second),
            validation(),
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn a_resolved_response_is_not_accepted_at_a_post_consumer() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = unsolicited_parties()?;
    let started = parties.sp.start_sso(
        &parties.idp_metadata,
        StartSso::redirect().response_binding(SsoResponseBinding::Post),
    )?;
    assert_eq!(started.pending.acs().binding(), SsoResponseBinding::Post);

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.initiate_sso_artifact(
        &parties.sp_metadata,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;

    assert!(matches!(
        parties.sp.finish_sso(
            &parties.idp_metadata,
            &started.pending,
            Inbound::artifact(delivered, resolved),
            validation(),
        ),
        Err(SamlError::UnsupportedBinding { .. })
    ));
    Ok(())
}

fn strip_embedded_signatures(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut rest = xml;
    let mut stripped = String::new();
    while let Some(start) = rest.find("<ds:Signature") {
        stripped.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find("</ds:Signature>")
            .ok_or("unterminated XML signature")?;
        rest = &after[end + "</ds:Signature>".len()..];
    }
    stripped.push_str(rest);
    Ok(stripped)
}

fn sign_response(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = read_private_key(PRIVKEY, None)?;
    Ok(sign_saml_xml(xml, true, &key, CERT, RSA_SHA256, &[], None)?)
}

/// A pending login and the unsigned `<Response>` the identity provider
/// built for it.
fn unsigned_response(
    parties: &Parties,
    issued: &mut IssuedArtifacts,
) -> Result<(PendingAuthnRequest, String), Box<dyn std::error::Error>> {
    let (pending, request) = requested(parties, None)?;
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        issued,
    )?;
    let resolved = resolve(parties, &delivered_by(&response)?, issued)?;
    let xml = strip_embedded_signatures(resolved.xml())?;
    assert_eq!(
        xml.matches(&format!("Destination=\"{SP_ACS_ARTIFACT}\""))
            .count(),
        1
    );
    Ok((pending, xml))
}

/// The identity provider stores `xml`, and the service provider resolves the
/// artifact and finishes the login.
fn store_and_finish(
    parties: &Parties,
    pending: &PendingAuthnRequest,
    xml: &str,
    issued: &mut IssuedArtifacts,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let artifact = parties
        .idp
        .issue_artifact(&parties.sp_metadata, xml, 0, issued)?;
    let delivered = DeliveredArtifact::from_form(&[FormField::new("SAMLart", artifact.as_str())])?;
    resolve_and_finish(parties, pending, delivered, issued)
}

#[test]
fn a_signed_artifact_response_may_omit_destination() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let without_destination = xml.replace(&format!(" Destination=\"{SP_ACS_ARTIFACT}\""), "");
    assert!(!without_destination.contains("Destination="));

    let session = store_and_finish(
        &parties,
        &pending,
        &sign_response(&without_destination)?,
        &mut issued,
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_artifact_response_destination_must_be_the_assertion_consumer(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let elsewhere = xml.replace(
        &format!("Destination=\"{SP_ACS_ARTIFACT}\""),
        &format!("Destination=\"{SP_ACS_POST}\""),
    );

    let result = store_and_finish(&parties, &pending, &sign_response(&elsewhere)?, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn an_unsigned_artifact_response_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;

    let result = store_and_finish(&parties, &pending, &xml, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::SignatureMissing)
    ));
    Ok(())
}

#[test]
fn a_response_resolved_from_another_identity_provider_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = unsolicited_parties()?;
    let other = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new("https://other-idp.example.com/metadata")?,
            SsoEndpoint::redirect("https://other-idp.example.com/sso")?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://other-idp.example.com/artifact")?,
        ))
        .credentials(signing_credentials())
        .build()?,
    );
    let other_metadata = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://other-idp.example.com/metadata")?,
        other.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = other.initiate_sso_artifact(
        &parties.sp_metadata,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolution = parties.sp.resolve_artifact(
        &other_metadata,
        delivered.artifact(),
        confidential(),
        validation(),
    )?;
    let answer = other.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        confidential(),
    )?;
    let resolved = resolution.finish(answer.response().envelope())?;

    assert!(matches!(
        parties.sp.accept_unsolicited_sso(
            &parties.idp_metadata,
            Inbound::artifact(delivered, resolved),
            validation(),
        ),
        Err(SamlError::IssuerMismatch { .. })
    ));
    Ok(())
}

#[test]
fn service_provider_metadata_publishes_the_artifact_consumer(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let document =
        saml_rs::xml::dom::parse_document(parties.sp.metadata_xml(), crate::XmlLimits::default())?;
    let descriptor = document
        .root
        .children
        .iter()
        .find(|node| node.local_name == "SPSSODescriptor")
        .ok_or("missing SPSSODescriptor")?;
    let consumers: Vec<(&str, &str)> = descriptor
        .children
        .iter()
        .filter(|node| node.local_name == "AssertionConsumerService")
        .filter_map(|node| Some((node.attr("Binding")?, node.attr("Location")?)))
        .collect();
    assert_eq!(
        consumers,
        [
            (
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                SP_ACS_POST
            ),
            (
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                SP_ACS_ARTIFACT
            ),
        ]
    );
    Ok(())
}

#[test]
fn a_pending_artifact_login_survives_a_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, request) = requested(&parties, None)?;
    let snapshot = pending.snapshot();
    assert_eq!(snapshot.acs_binding, "artifact");
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;
    assert_eq!(restored.acs().binding(), SsoResponseBinding::Artifact);
    assert_eq!(restored.acs(), pending.acs());

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let session = follow_redirect_and_finish(&parties, &restored, &response, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_unsolicited_artifact_is_not_sent_when_the_default_consumer_has_another_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    assert!(matches!(
        parties.idp.initiate_sso_artifact(
            &parties.sp_metadata,
            SsoAssertion::new(principal()),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            &mut IssuedArtifacts::expire_after(ARTIFACT_LIFETIME)
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn an_unsolicited_artifact_goes_to_the_default_artifact_consumer(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::artifact(SP_ACS_ARTIFACT)?.with_index(1),
        )
        .acs_endpoint(
            AcsEndpoint::artifact("https://sp.example.com/acs/default-artifact")?
                .with_index(2)
                .with_default(),
        )
        .credentials(signing_credentials())
        .build()?,
    );
    let sp_metadata = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.initiate_sso_artifact(
        &sp_metadata,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::post_form(0)),
        &mut issued,
    )?;
    assert_eq!(
        response.post_form()?.action().as_str(),
        "https://sp.example.com/acs/default-artifact"
    );

    let delivered = DeliveredArtifact::from_form(response.post_form()?.fields())?;
    let resolution = sp.resolve_artifact(
        &parties.idp_metadata,
        delivered.artifact(),
        confidential(),
        validation(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        confidential(),
    )?;
    let resolved = resolution.finish(answer.response().envelope())?;
    let session = sp.accept_unsolicited_sso(
        &parties.idp_metadata,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_artifact_must_be_delivered_once_and_be_a_saml_v2_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    const ARTIFACT: &str = "AAQAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D";
    let delivered = DeliveredArtifact::from_query(&format!("?SAMLart={ARTIFACT}&other=1"))?;
    assert_eq!(delivered.relay_state(), None);
    assert_eq!(delivered.artifact().endpoint_index(), 0);

    assert!(matches!(
        DeliveredArtifact::from_query("RelayState=state"),
        Err(SamlError::MissingBindingParameter { name: "SAMLart" })
    ));
    for (query, repeated) in [
        (format!("SAMLart={ARTIFACT}&SAMLart={ARTIFACT}"), "SAMLart"),
        (
            format!("SAMLart={ARTIFACT}&RelayState=a&RelayState=b"),
            "RelayState",
        ),
    ] {
        assert!(
            matches!(
                DeliveredArtifact::from_query(&query),
                Err(SamlError::DuplicateBindingParameter { name }) if name == repeated
            ),
            "{query}"
        );
    }
    // Type code 0x0001 is a SAML V1.1 artifact.
    assert!(matches!(
        DeliveredArtifact::from_query(
            "SAMLart=AAEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D"
        ),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        DeliveredArtifact::from_form(&[FormField::new("SAMLResponse", "PHNhbWw+")]),
        Err(SamlError::MissingBindingParameter { name: "SAMLart" })
    ));
    Ok(())
}

#[test]
fn a_bearer_recipient_must_be_the_consumer_the_artifact_was_delivered_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let recipient = format!("Recipient=\"{SP_ACS_ARTIFACT}\"");
    assert_eq!(xml.matches(&recipient).count(), 1);
    let elsewhere = xml.replace(&recipient, &format!("Recipient=\"{SP_ACS_POST}\""));

    let result = store_and_finish(&parties, &pending, &sign_response(&elsewhere)?, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::SubjectConfirmationInvalid {
            reason: SubjectConfirmationReason::RecipientMismatch
        })
    ));
    Ok(())
}

#[test]
fn a_request_for_a_posted_response_is_not_answered_with_an_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let started = parties
        .sp
        .start_sso(&parties.idp_metadata, StartSso::redirect())?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let request = parties.idp.receive_sso(
        &parties.sp_metadata,
        Inbound::redirect(url.query().ok_or("missing query")?),
        validation(),
    )?;
    assert_eq!(
        request.message().protocol_binding(),
        Some(SsoResponseBinding::Post)
    );

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    assert!(matches!(
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            SsoAssertion::new(principal()),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            &mut issued
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
fn redirect_idp_builder() -> Result<IdpConfigBuilder, SamlError> {
    Ok(IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::redirect(IDP_SSO_REDIRECT)?,
    ))
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_assertion_parties(
    idp: IdpConfigBuilder,
) -> Result<Parties, Box<dyn std::error::Error>> {
    let encryption = || XmlPolicy {
        encryption: XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
        ..XmlPolicy::default()
    };
    let idp = IdentityProvider::new(
        idp.artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new(RESOLUTION_URL)?,
        ))
        .credentials(signing_credentials())
        .xml(encryption())
        .build()?,
    );
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::artifact(SP_ACS_ARTIFACT)?,
        )
        .credentials(signing_credentials().with_decryption_credential(
            saml_rs::X509Credential::new(CertificatePem::new(CERT), PrivateKeyPem::new(PRIVKEY)),
        ))
        .xml(encryption())
        .build()?,
    );
    Ok(Parties {
        idp_metadata: IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
        sp_metadata: SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
        idp,
        sp,
    })
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn an_encrypted_assertion_delivered_as_an_artifact_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = encrypted_assertion_parties(redirect_idp_builder()?)?;
    let (pending, request) = requested(&parties, None)?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    assert_eq!(response.session_index(), None);
    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    assert!(resolved.xml().contains("EncryptedAssertion"));
    assert!(!resolved.xml().contains(USER));

    let session = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn an_artifact_response_returns_the_session_index_of_its_encrypted_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = encrypted_assertion_parties(
        redirect_idp_builder()?.slo_endpoint(SloEndpoint::redirect("https://idp.example.com/slo")?),
    )?;
    let (pending, request) = requested(&parties, None)?;

    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    assert!(resolved.xml().contains("EncryptedAssertion"));

    let session = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    )?;
    let accepted = session
        .logout_subject()
        .ok_or("accepted session is missing a logout subject")?;
    assert_eq!(
        response.session_index().map(std::slice::from_ref),
        Some(accepted.session_indexes())
    );
    Ok(())
}

#[test]
fn an_artifact_for_another_protocol_message_does_not_establish_a_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (pending, _) = requested(&parties, None)?;
    let logout = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer></samlp:LogoutRequest>"#
    );

    let result = store_and_finish(&parties, &pending, &logout, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::ProtocolProfile(message)) if message == "artifact must resolve to a protocol Response"
    ));
    Ok(())
}

#[test]
fn a_typed_sso_artifact_response_is_withheld_without_confidentiality(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let (_, request) = requested(&parties, None)?;
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        delivered.artifact(),
        confidential(),
        validation(),
    )?;

    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        SoapChannel::new(
            PartyAuthentication::Mutual,
            MessageIntegrity::Protected,
            MessageConfidentiality::Unattested,
        ),
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::InsufficientChannelProtection)
    );
    assert!(!answer.response().envelope().contains("Assertion"));
    Ok(())
}
