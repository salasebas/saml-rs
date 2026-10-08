//! Web Browser SSO with the `<Response>` delivered as an HTTP-Artifact,
//! through the typed identity provider and service provider.
//!
//! The identity provider stores the response and hands the browser an
//! artifact. The service provider reads the artifact at its assertion
//! consumer, resolves it over SOAP, and establishes the session. The
//! deployment still performs HTTP and TLS.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{construct_saml_signature, keys::load_private_key};
use saml_rs::error::SubjectConfirmationReason;
use saml_rs::{
    AcsEndpoint, ArtifactDelivery, ArtifactDereference, ArtifactResolutionService, ArtifactUses,
    AuthnRequest, BrowserInput, CertificatePem, Credentials, DeliveredArtifact, EndpointUrl,
    EntityId, FormField, Idp, IdpConfig, IdpDescriptor, IssuedArtifacts, IssuedMessage,
    MetadataTrustPolicy, NameId, Outbound, PendingAuthnRequest, PrivateKeyPem, Received,
    RelayStateParam, ReplayPolicy, ResolvedProtocolMessage, RespondSso, Saml, SamlError,
    SamlValidationContext, SoapChannel, Sp, SpConfig, SpDescriptor, SsoEndpoint, SsoResponse,
    SsoResponseBinding, SsoSession, StartSso, Status, Subject, SubordinateStatusCode,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{XmlEncryptionPolicy, XmlPolicy};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_ARTIFACT: &str = "https://sp.example.com/acs/artifact";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const RESOLUTION_URL: &str = "https://idp.example.com/artifact";
const USER: &str = "user@example.com";
const AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

struct Parties {
    idp: Saml<Idp>,
    sp: Saml<Sp>,
    idp_metadata: IdpDescriptor,
    sp_metadata: SpDescriptor,
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn parties() -> Result<Parties, SamlError> {
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new(RESOLUTION_URL)?,
            ))
            .credentials(credentials())
            .build()?,
    )?;
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
            .acs_endpoint(AcsEndpoint::artifact(SP_ACS_ARTIFACT)?)
            .credentials(credentials())
            .build()?,
    )?;
    let idp_metadata = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let sp_metadata = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok(Parties {
        idp,
        sp,
        idp_metadata,
        sp_metadata,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(NameId::new(USER, None), Vec::new())
}

fn confidential() -> SoapChannel {
    SoapChannel::mutually_authenticated_confidential()
}

/// The service provider asks for an artifact response, and the identity
/// provider receives that request.
fn requested(
    parties: &Parties,
    relay_state: RelayStateParam,
) -> Result<(PendingAuthnRequest, Received<AuthnRequest>), Box<dyn std::error::Error>> {
    let started = parties.sp.start_sso(
        &parties.idp_metadata,
        StartSso::redirect()
            .response_binding(SsoResponseBinding::Artifact)
            .relay_state(relay_state),
    )?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let request = parties.idp.receive_sso(
        &parties.sp_metadata,
        BrowserInput::<AuthnRequest>::redirect(url.query().ok_or("missing query")?),
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
    let (pending, request) = requested(&parties, RelayStateParam::absent())?;
    assert_eq!(pending.response_binding(), SsoResponseBinding::Artifact);
    assert_eq!(pending.acs().location().as_str(), SP_ACS_ARTIFACT);

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
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
fn relay_state_travels_with_the_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let relay_state = RelayStateParam::try_from_option(Some("state & more=1"))?;
    let (pending, request) = requested(&parties, relay_state.clone())?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;

    let url = Url::parse(response.redirect_url()?)?;
    let delivered = DeliveredArtifact::from_query(url.query().ok_or("missing query")?)?;
    assert_eq!(delivered.relay_state(), &relay_state);

    let session = follow_redirect_and_finish(&parties, &pending, &response, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn a_relay_state_the_service_provider_did_not_send_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (pending, request) = requested(
        &parties,
        RelayStateParam::try_from_option(Some("expected"))?,
    )?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0))
            .relay_state(RelayStateParam::try_from_option(Some("swapped"))?),
        &mut issued,
    )?;

    let result = follow_redirect_and_finish(&parties, &pending, &response, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::RelayStateMismatch { .. })
    ));
    Ok(())
}

#[test]
fn a_relay_state_longer_than_80_bytes_is_not_delivered() -> Result<(), Box<dyn std::error::Error>> {
    let query = |relay_state: String| {
        format!(
            "SAMLart=AAQAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D&RelayState={relay_state}"
        )
    };
    let delivered = DeliveredArtifact::from_query(&query("r".repeat(80)))?;
    assert_eq!(
        delivered.relay_state().as_deref(),
        Some("r".repeat(80).as_str())
    );
    assert!(matches!(
        DeliveredArtifact::from_query(&query("r".repeat(81))),
        Err(SamlError::Invalid(_))
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
        BrowserInput::<SsoResponse>::artifact(delivered, resolved),
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
        ArtifactDereference::web_browser_sso(confidential())?,
        &mut ArtifactUses::enforce_single_use(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        issued,
        confidential(),
    )?;
    Ok(resolution.finish(answer.envelope())?)
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
    let relay_state = RelayStateParam::try_from_option(Some("form-state"))?;
    let (pending, request) = requested(&parties, relay_state)?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
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
        Err(SamlError::UndefinedBinding)
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
    let (pending, request) = requested(&parties, RelayStateParam::absent())?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)).status(
            Status::responder().with_subordinate(SubordinateStatusCode::try_new(AUTHN_FAILED)?),
        ),
        &mut issued,
    )?;

    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    assert_eq!(resolved.local_name(), "Response");
    assert!(!resolved.xml().contains("Assertion"));

    let result = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        BrowserInput::<SsoResponse>::artifact(delivered, resolved),
        validation(),
    );
    match result {
        Err(SamlError::StatusNotSuccess { top, second }) => {
            assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Responder");
            assert_eq!(second.as_deref(), Some(AUTHN_FAILED));
        }
        other => return Err(format!("expected a status error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn an_unsolicited_artifact_response_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let relay_state = RelayStateParam::try_from_option(Some("https://sp.example.com/app"))?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.initiate_sso_artifact(
        &parties.sp_metadata,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)).relay_state(relay_state.clone()),
        &mut issued,
    )?;
    assert!(response.redirect_url()?.starts_with(SP_ACS_ARTIFACT));

    let delivered = delivered_by(&response)?;
    assert_eq!(delivered.relay_state(), &relay_state);
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    let session = parties.sp.accept_unsolicited_sso(
        &parties.idp_metadata,
        BrowserInput::<SsoResponse>::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn a_request_for_an_artifact_response_is_not_answered_over_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (_pending, request) = requested(&parties, RelayStateParam::absent())?;
    assert_eq!(
        request.message().protocol_binding(),
        Some(SsoResponseBinding::Artifact)
    );
    assert!(matches!(
        parties.idp.respond_sso(
            &parties.sp_metadata,
            &request,
            subject(),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn a_missing_resolution_service_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let (_pending, request) = requested(&parties, RelayStateParam::absent())?;
    let mut issued = IssuedArtifacts::new();
    assert!(matches!(
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            subject(),
            RespondSso::artifact(ArtifactDelivery::redirect(7)),
            &mut issued,
        ),
        Err(SamlError::MissingMetadata(_))
    ));
    Ok(())
}

#[test]
fn a_message_resolved_from_another_artifact_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let (pending, request) = requested(&parties, RelayStateParam::absent())?;
    let mut issued = IssuedArtifacts::new();
    let respond = |issued: &mut IssuedArtifacts| {
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            subject(),
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
            BrowserInput::<SsoResponse>::artifact(first, resolved_second),
            validation(),
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn a_resolved_response_is_not_accepted_at_a_post_consumer() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let started = parties
        .sp
        .start_sso(&parties.idp_metadata, StartSso::redirect())?;
    assert_eq!(started.pending.response_binding(), SsoResponseBinding::Post);

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.initiate_sso_artifact(
        &parties.sp_metadata,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;

    assert!(matches!(
        parties.sp.finish_sso(
            &parties.idp_metadata,
            &started.pending,
            BrowserInput::<SsoResponse>::artifact(delivered, resolved),
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
    let key = load_private_key(PRIVKEY, None)?;
    Ok(construct_saml_signature(
        xml,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

/// A pending login and the unsigned `<Response>` the identity provider
/// built for it.
fn unsigned_response(
    parties: &Parties,
    issued: &mut IssuedArtifacts,
) -> Result<(PendingAuthnRequest, String), Box<dyn std::error::Error>> {
    let (pending, request) = requested(parties, RelayStateParam::absent())?;
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
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
    xml: String,
    issued: &mut IssuedArtifacts,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let artifact = parties.idp.issue_artifact(
        &parties.sp_metadata,
        IssuedMessage::web_browser_sso_response(xml)?,
        0,
        issued,
    )?;
    let delivered = DeliveredArtifact::from_form(&[FormField::new("SAMLart", artifact.as_str())])?;
    resolve_and_finish(parties, pending, delivered, issued)
}

#[test]
fn a_signed_artifact_response_may_omit_destination() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let without_destination = xml.replace(&format!(" Destination=\"{SP_ACS_ARTIFACT}\""), "");
    assert!(!without_destination.contains("Destination="));

    let session = store_and_finish(
        &parties,
        &pending,
        sign_response(&without_destination)?,
        &mut issued,
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_artifact_response_destination_must_be_the_assertion_consumer(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let elsewhere = xml.replace(
        &format!("Destination=\"{SP_ACS_ARTIFACT}\""),
        &format!("Destination=\"{SP_ACS_POST}\""),
    );

    let result = store_and_finish(&parties, &pending, sign_response(&elsewhere)?, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn an_unsigned_artifact_response_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;

    let result = store_and_finish(&parties, &pending, xml, &mut issued);
    assert!(matches!(
        saml_error(result),
        Some(SamlError::SignatureMissing)
    ));
    Ok(())
}

#[test]
fn a_response_resolved_from_another_identity_provider_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let other = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://other-idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::redirect("https://other-idp.example.com/sso")?)
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new("https://other-idp.example.com/artifact")?,
            ))
            .credentials(credentials())
            .build()?,
    )?;
    let other_metadata = IdpDescriptor::from_metadata_xml(
        other.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let mut issued = IssuedArtifacts::new();
    let response = other.initiate_sso_artifact(
        &parties.sp_metadata,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolution = parties.sp.resolve_artifact(
        &other_metadata,
        delivered.artifact(),
        ArtifactDereference::web_browser_sso(confidential())?,
        &mut ArtifactUses::enforce_single_use(),
    )?;
    let answer = other.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        confidential(),
    )?;
    let resolved = resolution.finish(answer.envelope())?;

    assert!(matches!(
        parties.sp.accept_unsolicited_sso(
            &parties.idp_metadata,
            BrowserInput::<SsoResponse>::artifact(delivered, resolved),
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
    let document = saml_rs::xml::dom::parse(parties.sp.metadata_xml())?;
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
    let (pending, request) = requested(&parties, RelayStateParam::absent())?;
    let snapshot = pending.snapshot();
    assert_eq!(snapshot.expected_binding, "artifact");
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;
    assert_eq!(restored.response_binding(), SsoResponseBinding::Artifact);
    assert_eq!(restored.acs(), pending.acs());

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let session = follow_redirect_and_finish(&parties, &restored, &response, &mut issued)?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}

#[test]
fn an_unsolicited_artifact_goes_to_the_default_artifact_consumer(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::artifact(SP_ACS_ARTIFACT)?.with_index(1))
            .acs_endpoint(
                AcsEndpoint::artifact("https://sp.example.com/acs/default-artifact")?
                    .with_index(2)
                    .mark_default(),
            )
            .credentials(credentials())
            .build()?,
    )?;
    let sp_metadata = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.initiate_sso_artifact(
        &sp_metadata,
        subject(),
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
        ArtifactDereference::web_browser_sso(confidential())?,
        &mut ArtifactUses::enforce_single_use(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        confidential(),
    )?;
    let resolved = resolution.finish(answer.envelope())?;
    let session = sp.accept_unsolicited_sso(
        &parties.idp_metadata,
        BrowserInput::<SsoResponse>::artifact(delivered, resolved),
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
    assert_eq!(delivered.relay_state(), &RelayStateParam::absent());
    assert_eq!(delivered.artifact().endpoint_index(), 0);

    for query in [
        "RelayState=state".to_string(),
        format!("SAMLart={ARTIFACT}&SAMLart={ARTIFACT}"),
        format!("SAMLart={ARTIFACT}&RelayState=a&RelayState=b"),
        // Type code 0x0001 is a SAML V1.1 artifact.
        "SAMLart=AAEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D".to_string(),
    ] {
        assert!(
            matches!(
                DeliveredArtifact::from_query(&query),
                Err(SamlError::Invalid(_))
            ),
            "{query}"
        );
    }
    assert!(matches!(
        DeliveredArtifact::from_form(&[FormField::new("SAMLResponse", "PHNhbWw+")]),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn a_bearer_recipient_must_be_the_consumer_the_artifact_was_delivered_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let (pending, xml) = unsigned_response(&parties, &mut issued)?;
    let recipient = format!("Recipient=\"{SP_ACS_ARTIFACT}\"");
    assert_eq!(xml.matches(&recipient).count(), 1);
    let elsewhere = xml.replace(&recipient, &format!("Recipient=\"{SP_ACS_POST}\""));

    let result = store_and_finish(&parties, &pending, sign_response(&elsewhere)?, &mut issued);
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
        BrowserInput::<AuthnRequest>::redirect(url.query().ok_or("missing query")?),
        validation(),
    )?;
    assert_eq!(
        request.message().protocol_binding(),
        Some(SsoResponseBinding::Post)
    );

    let mut issued = IssuedArtifacts::new();
    assert!(matches!(
        parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            subject(),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            &mut issued,
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn an_encrypted_assertion_delivered_as_an_artifact_establishes_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = || XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions()
            .with_insecure_software_rsa_key_transport_decryption_allowed(),
        ..XmlPolicy::default()
    };
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new(RESOLUTION_URL)?,
            ))
            .credentials(credentials())
            .xml(encryption())
            .build()?,
    )?;
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::artifact(SP_ACS_ARTIFACT)?)
            .credentials(Credentials {
                encryption_certificate: Some(CertificatePem::new(CERT)),
                decryption_key: Some(PrivateKeyPem::new(PRIVKEY)),
                ..credentials()
            })
            .xml(encryption())
            .build()?,
    )?;
    let parties = Parties {
        idp_metadata: IdpDescriptor::from_metadata_xml(
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
        sp_metadata: SpDescriptor::from_metadata_xml(
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
        idp,
        sp,
    };
    let (pending, request) = requested(&parties, RelayStateParam::absent())?;

    let mut issued = IssuedArtifacts::new();
    let response = parties.idp.respond_sso_artifact(
        &parties.sp_metadata,
        &request,
        subject(),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut issued,
    )?;
    let delivered = delivered_by(&response)?;
    let resolved = resolve(&parties, &delivered, &mut issued)?;
    assert!(resolved.xml().contains("EncryptedAssertion"));
    assert!(!resolved.xml().contains(USER));

    let session = parties.sp.finish_sso(
        &parties.idp_metadata,
        &pending,
        BrowserInput::<SsoResponse>::artifact(delivered, resolved),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), USER);
    Ok(())
}
