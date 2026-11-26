//! Identity-provider receipt of an `AuthnRequest` from a service provider
//! whose metadata sets `AuthnRequestsSigned`.
//!
//! SAML Metadata §2.4.4 as amended by Errata 05 E7.
#![cfg(crypto)]

mod common;

#[path = "common/tag_prefixes.rs"]
mod tag_prefixes;

use common::signing_credentials;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, ArtifactDelivery, ArtifactResolutionService, AuthnRequest,
    AuthnRequestRefusalReason, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, ClockSkew,
    DeliveredArtifact, EndpointUrl, EntityId, IdentityProvider, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, InMemoryReplayCache, Inbound, IssuedArtifacts, MessageAuthentication,
    MetadataTrustPolicy, Outbound, RelayState, ReplayPolicy, RequestAgePolicy, RespondSso,
    SamlError, SamlValidationContext, ServiceProvider, SignatureAlgorithm, SoapChannel, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponseBinding, StartSso, Started, Status,
    StatusMessage,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp(
    authn_request_signing: AuthnRequestSigningPolicy,
) -> Result<saml_rs::ServiceProvider, SamlError> {
    sp_with_acs(authn_request_signing, AcsEndpoint::post(SP_ACS)?)
}

fn sp_with_acs(
    authn_request_signing: AuthnRequestSigningPolicy,
    acs: AcsEndpoint,
) -> Result<ServiceProvider, SamlError> {
    let mut validation = SpValidationPolicy::default();
    validation.authn_request_signing = authn_request_signing;
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, acs.with_default())
            .templates(tag_prefixes::templates("p", "a"))
            .credentials(signing_credentials())
            .validation(validation)
            .build()?,
    ))
}

fn idp(validation: IdpValidationPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_POST)?)
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    ))
}

fn descriptors(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn post_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    Ok(Inbound::post(outbound.post_form()?.fields().to_vec()))
}

fn redirect_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    let url = Url::parse(outbound.redirect_url()?)?;
    Ok(Inbound::redirect(url.query().unwrap_or_default()))
}

#[test]
fn elliptic_curve_signing_rejects_incompatible_credentials_during_configuration(
) -> Result<(), Box<dyn std::error::Error>> {
    for (signature, credentials) in [
        (
            SignatureAlgorithm::Custom(
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256".into(),
            ),
            signing_credentials(),
        ),
        (SignatureAlgorithm::EcdsaSha384, signing_credentials()),
        (SignatureAlgorithm::EcdsaSha512, signing_credentials()),
        #[cfg(not(feature = "crypto-fips"))]
        (
            SignatureAlgorithm::Ed25519,
            saml_rs::Credentials::default().with_signing_credential(saml_rs::X509Credential::new(
                saml_rs::CertificatePem::new(include_str!("fixtures/key/prime256v1/cert.pem")),
                saml_rs::PrivateKeyPem::new(include_str!(
                    "fixtures/key/prime256v1/privkey.pkcs8.pem"
                )),
            )),
        ),
    ] {
        let mut algorithms = AlgorithmPolicy::default();
        algorithms.signature = signature.clone();
        let mut policy = SpValidationPolicy::default();
        policy.authn_request_signing = AuthnRequestSigningPolicy::Sign;
        let sp = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials.clone())
            .algorithms(algorithms.clone())
            .validation(policy)
            .build();
        assert!(
            matches!(sp, Err(SamlError::Invalid(_))),
            "SP {signature:?}: {sp:?}"
        );
        let idp = IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(credentials)
        .algorithms(algorithms)
        .build();
        assert!(
            matches!(idp, Err(SamlError::Invalid(_))),
            "IdP {signature:?}: {idp:?}"
        );
    }
    Ok(())
}

#[test]
fn unsigned_browser_request_is_rejected_when_sp_metadata_sets_authn_requests_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    let unsigned_sp = sp(AuthnRequestSigningPolicy::DoNotSign)?;
    let idp = idp(IdpValidationPolicy::default())?;
    let (signing_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;
    assert!(signing_sp
        .metadata_xml()
        .contains("AuthnRequestsSigned=\"true\""));

    let unsigned_post = unsigned_sp.start_sso(
        &idp_descriptor,
        StartSso::post().relay_state(RelayState::try_new("login-42")?),
    )?;
    let unsigned_redirect = unsigned_sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(RelayState::try_new("login-42")?),
    )?;
    for (started, input) in [
        (&unsigned_post, post_input(&unsigned_post.outbound)?),
        (
            &unsigned_post,
            Inbound::simple_sign(unsigned_post.outbound.post_form()?.fields().to_vec()),
        ),
        (
            &unsigned_redirect,
            redirect_input(&unsigned_redirect.outbound)?,
        ),
    ] {
        let refusal = match idp.receive_sso(&signing_descriptor, input, validation()) {
            Err(SamlError::AuthnRequestRefused { refusal, .. }) => refusal,
            other => return Err(format!("expected a sendable SAML refusal, got {other:?}").into()),
        };
        assert!(matches!(
            idp.respond_sso_refusal(&signing_descriptor, &refusal, RespondSso::simple_sign()),
            Err(SamlError::Invalid(_))
        ));
        let options = RespondSso::post().status_message("Send a signed authentication request.");
        let response = idp.respond_sso_refusal(&signing_descriptor, &refusal, options)?;
        let form = response.post_form()?;
        assert_eq!(form.action().as_str(), SP_ACS);
        assert_eq!(form.value("RelayState"), Some("login-42"));
        let xml = base64::engine::general_purpose::STANDARD
            .decode(form.value("SAMLResponse").ok_or("missing SAMLResponse")?)?;
        let document = roxmltree::Document::parse(std::str::from_utf8(&xml)?)?;
        let root = document.root_element();
        assert_eq!(
            root.attribute("InResponseTo"),
            Some(started.pending.request_id().as_str())
        );
        assert!(!root
            .children()
            .any(|child| matches!(child.tag_name().name(), "Assertion" | "EncryptedAssertion")));
        match unsigned_sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::post(form.fields().to_vec()),
            validation(),
        ) {
            Err(SamlError::StatusNotSuccess {
                status,
                status_message,
                ..
            }) => {
                assert_eq!(status, Status::requester());
                assert_eq!(
                    status_message.as_ref().map(StatusMessage::as_str),
                    Some("Send a signed authentication request.")
                );
            }
            other => {
                return Err(format!("expected a verified requester error, got {other:?}").into())
            }
        }
    }

    let signed_post = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let encoded = signed_post
        .outbound
        .post_form()?
        .value("SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
    assert!(xml.contains("<p:AuthnRequest ") && xml.contains("<a:Issuer>"));
    let signed_redirect = signing_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    for (started, input) in [
        (&signed_post, post_input(&signed_post.outbound)?),
        (
            &signed_post,
            Inbound::simple_sign(signed_post.outbound.post_form()?.fields().to_vec()),
        ),
        (&signed_redirect, redirect_input(&signed_redirect.outbound)?),
    ] {
        let received = idp.receive_sso(&signing_descriptor, input, validation())?;
        assert_eq!(received.message().id(), started.pending.request_id());
    }

    let (unsigned_descriptor, _) = descriptors(&unsigned_sp, &idp)?;
    let received = idp.receive_sso(
        &unsigned_descriptor,
        Inbound::simple_sign(unsigned_post.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(received.message().id(), unsigned_post.pending.request_id());
    Ok(())
}

#[test]
fn sign_when_idp_wants_signs_only_for_an_idp_whose_metadata_sets_the_flag(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(AuthnRequestSigningPolicy::SignWhenIdpWants)?;
    assert!(sp.metadata_xml().contains(" AuthnRequestsSigned=\"false\""));
    let mut strict_policy = IdpValidationPolicy::default();
    strict_policy.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
    let strict = idp(strict_policy)?;
    let permissive = idp(IdpValidationPolicy::default())?;

    let (sp_descriptor, strict_descriptor) = descriptors(&sp, &strict)?;
    let post = sp.start_sso(&strict_descriptor, StartSso::post())?;
    let redirect = sp.start_sso(&strict_descriptor, StartSso::redirect())?;
    let simple_sign = sp.start_sso(&strict_descriptor, StartSso::simple_sign())?;
    for input in [
        post_input(&post.outbound)?,
        redirect_input(&redirect.outbound)?,
        Inbound::simple_sign(simple_sign.outbound.post_form()?.fields().to_vec()),
    ] {
        let received = strict.receive_sso(&sp_descriptor, input, validation())?;
        assert_eq!(
            received.authentication(),
            MessageAuthentication::Authenticated
        );
    }

    let (sp_descriptor, permissive_descriptor) = descriptors(&sp, &permissive)?;
    let post = sp.start_sso(&permissive_descriptor, StartSso::post())?;
    let redirect = sp.start_sso(&permissive_descriptor, StartSso::redirect())?;
    for input in [
        post_input(&post.outbound)?,
        redirect_input(&redirect.outbound)?,
    ] {
        let received = permissive.receive_sso(&sp_descriptor, input, validation())?;
        assert_eq!(
            received.authentication(),
            MessageAuthentication::Unauthenticated
        );
    }
    let simple_sign = sp.start_sso(&permissive_descriptor, StartSso::simple_sign());
    assert!(
        matches!(simple_sign, Err(SamlError::Invalid(_))),
        "{simple_sign:?}"
    );
    Ok(())
}

#[test]
fn sign_when_idp_wants_requires_a_signing_credential_to_build(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = SpValidationPolicy::default();
    policy.authn_request_signing = AuthnRequestSigningPolicy::SignWhenIdpWants;
    let config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
        .validation(policy)
        .build();
    assert!(
        matches!(&config, Err(SamlError::MissingKey(key)) if key == "signing_credential"),
        "{config:?}"
    );
    Ok(())
}

#[test]
fn default_idp_reports_whether_a_signature_authenticated_the_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(IdpValidationPolicy::default())?;
    let unsigned_sp = sp(AuthnRequestSigningPolicy::DoNotSign)?;
    let (receiving_descriptor, idp_descriptor) = descriptors(&unsigned_sp, &idp)?;
    assert!(!unsigned_sp
        .metadata_xml()
        .contains("AuthnRequestsSigned=\"true\""));
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    for (sender, expected) in [
        (&signing_sp, MessageAuthentication::Authenticated),
        (&unsigned_sp, MessageAuthentication::Unauthenticated),
    ] {
        let post = sender.start_sso(&idp_descriptor, StartSso::post())?;
        let redirect = sender.start_sso(&idp_descriptor, StartSso::redirect())?;
        for input in [
            post_input(&post.outbound)?,
            Inbound::simple_sign(post.outbound.post_form()?.fields().to_vec()),
            redirect_input(&redirect.outbound)?,
        ] {
            let received = idp.receive_sso(&receiving_descriptor, input, validation())?;
            assert_eq!(received.authentication(), expected);
        }
    }
    Ok(())
}

#[test]
fn strict_idp_can_refuse_an_unsigned_request_but_cannot_use_a_removed_acs(
) -> Result<(), Box<dyn std::error::Error>> {
    let unsigned_sp = sp(AuthnRequestSigningPolicy::DoNotSign)?;
    let permissive = idp(IdpValidationPolicy::default())?;
    let (_, old_idp_descriptor) = descriptors(&unsigned_sp, &permissive)?;
    let started = unsigned_sp.start_sso(&old_idp_descriptor, StartSso::post())?;

    let mut policy = IdpValidationPolicy::default();
    policy.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
    let strict = idp(policy)?;
    let updated_sp = sp_with_acs(
        AuthnRequestSigningPolicy::Sign,
        AcsEndpoint::post("https://sp.example.com/acs/current")?,
    )?;
    let (updated_descriptor, _) = descriptors(&updated_sp, &strict)?;
    let refusal = match strict.receive_sso(
        &updated_descriptor,
        post_input(&started.outbound)?,
        validation(),
    ) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => refusal,
        other => {
            return Err(
                format!("expected a SAML refusal under RequireSigned, got {other:?}").into(),
            )
        }
    };
    assert!(matches!(
        strict.respond_sso_refusal(&updated_descriptor, &refusal, RespondSso::post()),
        Err(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

fn assert_requester_error(
    sp: &ServiceProvider,
    idp_descriptor: &IdpDescriptor,
    started: &Started<AuthnRequest>,
    response: &Outbound<saml_rs::SsoResponse>,
    relay_state: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let form = response.post_form()?;
    assert_eq!(form.action().as_str(), SP_ACS);
    assert_eq!(form.value("RelayState"), relay_state);
    match sp.finish_sso(
        idp_descriptor,
        &started.pending,
        Inbound::post(form.fields().to_vec()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status, .. }) => {
            assert_eq!(status, Status::requester());
            Ok(())
        }
        other => Err(format!("expected a correlated requester error, got {other:?}").into()),
    }
}

#[test]
fn idp_requiring_signed_requests_returns_refusal_data_for_an_unsigned_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let unsigned_sp = sp(SpValidationPolicy::default().authn_request_signing)?;
    let permissive = idp(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&unsigned_sp, &permissive)?;
    assert!(!unsigned_sp
        .metadata_xml()
        .contains("AuthnRequestsSigned=\"true\""));
    let mut policy = IdpValidationPolicy::default();
    policy.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
    let strict = idp(policy)?;

    let post = unsigned_sp.start_sso(
        &idp_descriptor,
        StartSso::post().relay_state(RelayState::try_new("login-44")?),
    )?;
    let redirect = unsigned_sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(RelayState::try_new("login-44")?),
    )?;
    for (started, input) in [
        (&post, post_input(&post.outbound)?),
        (
            &post,
            Inbound::simple_sign(post.outbound.post_form()?.fields().to_vec()),
        ),
        (&redirect, redirect_input(&redirect.outbound)?),
    ] {
        let refusal = match strict.receive_sso(&sp_descriptor, input, validation()) {
            Err(SamlError::AuthnRequestRefused { refusal, .. }) => refusal,
            other => return Err(format!("expected a sendable SAML refusal, got {other:?}").into()),
        };
        assert_eq!(refusal.reason(), AuthnRequestRefusalReason::Unsigned);
        let response = strict.respond_sso_refusal(&sp_descriptor, &refusal, RespondSso::post())?;
        assert_requester_error(
            &unsigned_sp,
            &idp_descriptor,
            started,
            &response,
            started.pending.relay_state().map(RelayState::as_str),
        )?;
    }
    Ok(())
}

#[test]
fn idp_returns_refusal_data_for_a_request_outside_its_age_window(
) -> Result<(), Box<dyn std::error::Error>> {
    let unsigned_sp = sp(SpValidationPolicy::default().authn_request_signing)?;
    let idp = idp(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&unsigned_sp, &idp)?;
    let started = unsigned_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let later = SamlValidationContext::new(
        SystemTime::now() + Duration::from_secs(600),
        ReplayPolicy::NoCache,
    )
    .with_authn_request_age(RequestAgePolicy::Bounded {
        max_age: Duration::from_secs(60),
    });
    let refusal = match idp.receive_sso(&sp_descriptor, post_input(&started.outbound)?, later) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => refusal,
        other => return Err(format!("expected a sendable SAML refusal, got {other:?}").into()),
    };
    assert_eq!(
        refusal.reason(),
        AuthnRequestRefusalReason::OutsideAgeWindow
    );
    let response = idp.respond_sso_refusal(
        &sp_descriptor,
        &refusal,
        RespondSso::post().relay_state(RelayState::try_new("idp-chosen")?),
    )?;
    assert_requester_error(
        &unsigned_sp,
        &idp_descriptor,
        &started,
        &response,
        Some("idp-chosen"),
    )
}

fn age_bounded(now: SystemTime, cache: &mut InMemoryReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(now, ReplayPolicy::RequireCache(cache))
        .with_clock_skew(ClockSkew::strict())
        .with_authn_request_age(RequestAgePolicy::Bounded {
            max_age: Duration::from_secs(60),
        })
        .with_replay_retention(Duration::from_secs(120))
}

#[test]
fn a_signed_request_replayed_after_its_replay_entry_expired_is_refused_for_its_age(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    let idp = idp(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;
    let started = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received_at = SystemTime::now();
    let elapsed_seconds = Arc::new(AtomicU64::new(0));
    let cache_elapsed_seconds = Arc::clone(&elapsed_seconds);
    let mut cache = InMemoryReplayCache::with_clock(move || {
        received_at + Duration::from_secs(cache_elapsed_seconds.load(Ordering::SeqCst))
    });

    idp.receive_sso(
        &sp_descriptor,
        post_input(&started.outbound)?,
        age_bounded(received_at, &mut cache),
    )?;
    elapsed_seconds.store(180, Ordering::SeqCst);
    match idp.receive_sso(
        &sp_descriptor,
        post_input(&started.outbound)?,
        age_bounded(received_at + Duration::from_secs(180), &mut cache),
    ) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => {
            assert_eq!(
                refusal.reason(),
                AuthnRequestRefusalReason::OutsideAgeWindow
            );
            Ok(())
        }
        other => Err(format!("expected an age refusal of the replay, got {other:?}").into()),
    }
}

#[test]
fn unsigned_request_refusal_reaches_an_artifact_acs() -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp_with_acs(
        AuthnRequestSigningPolicy::Sign,
        AcsEndpoint::artifact(SP_ACS)?,
    )?;
    let unsigned_sp = sp_with_acs(
        AuthnRequestSigningPolicy::DoNotSign,
        AcsEndpoint::artifact(SP_ACS)?,
    )?;
    let idp = idp(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;
    let started = unsigned_sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().response_binding(SsoResponseBinding::Artifact),
    )?;
    let refusal = match idp.receive_sso(
        &sp_descriptor,
        redirect_input(&started.outbound)?,
        validation(),
    ) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => refusal,
        other => return Err(format!("expected a sendable SAML refusal, got {other:?}").into()),
    };
    let mut issued = IssuedArtifacts::expire_after(std::time::Duration::from_secs(60));
    let diagnostic = "Send a signed authentication request.";
    let response = idp.respond_sso_refusal_artifact(
        &sp_descriptor,
        &refusal,
        RespondSso::artifact(ArtifactDelivery::redirect(0))
            .relay_state(RelayState::try_new("login-43")?)
            .status_message(diagnostic),
        &mut issued,
    )?;
    let url = Url::parse(response.redirect_url()?)?;
    assert_eq!(url.path(), "/acs");
    let delivered = DeliveredArtifact::from_query(url.query().ok_or("missing artifact query")?)?;
    assert_eq!(
        delivered.relay_state().map(RelayState::as_str),
        Some("login-43")
    );
    let channel = SoapChannel::mutually_authenticated_confidential();
    let resolution = unsigned_sp.resolve_artifact(
        &idp_descriptor,
        delivered.artifact(),
        channel,
        validation(),
    )?;
    let answer = idp.answer_artifact_resolve(
        &sp_descriptor,
        resolution.request().envelope(),
        resolution.request().endpoint(),
        &mut issued,
        channel,
    )?;
    let resolved = resolution.finish(answer.response().envelope())?;
    match unsigned_sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::artifact(delivered, resolved),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess {
            status,
            status_message,
            ..
        }) => {
            assert_eq!(status, Status::requester());
            assert_eq!(
                status_message.as_ref().map(StatusMessage::as_str),
                Some(diagnostic)
            );
        }
        other => return Err(format!("expected a verified requester error, got {other:?}").into()),
    }
    Ok(())
}
