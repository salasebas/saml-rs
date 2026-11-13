//! Compatibility is the legacy permissive preset.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::{
    AcsEndpoint, BrowserInput, EntityId, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    LogoutPolicy, LogoutRequest, LogoutResponse, LogoutSignaturePolicy, LogoutSigning,
    LogoutSubject, MetadataTrustPolicy, NameId, Outbound, PendingLogoutRequest, ReplayPolicy,
    RespondSlo, Saml, SamlError, SamlValidationContext, SessionIndex, SloEndpoint, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSlo,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SLO_HTTPS: &str = "https://sp.example.com/slo/post";
const SP_SLO_HTTP: &str = "http://sp.example.com/slo/post";
const IDP_SSO: &str = "https://idp.example.com/sso/post";
const IDP_SLO_HTTPS: &str = "https://idp.example.com/slo/post";
const IDP_SLO_HTTP: &str = "http://idp.example.com/slo/post";

fn slo_accept_policy() -> LogoutPolicy {
    LogoutPolicy {
        requests: LogoutSignaturePolicy::RequireSigned,
        responses: LogoutSignaturePolicy::RequireSigned,
    }
}

fn sp_with_slo_accept() -> SpValidationPolicy {
    SpValidationPolicy::recommended()
}

fn idp_with_slo_accept() -> IdpValidationPolicy {
    IdpValidationPolicy::recommended()
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sp(slo: &str, policy: SpValidationPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .slo_endpoint(SloEndpoint::post(slo)?)
            .credentials(signing_credentials())
            .validation(policy)
            .build()?,
    )
}

fn idp(slo: &str, policy: IdpValidationPolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
            .slo_endpoint(SloEndpoint::post(slo)?)
            .credentials(signing_credentials())
            .validation(policy)
            .build()?,
    )
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn subject_with_session() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        NameId::new("alice@example.com", None),
        SessionIndex::try_new("_session")?,
    ))
}

fn subject_without_session() -> LogoutSubject {
    LogoutSubject::from_name_id(NameId::new("alice@example.com", None))
}

fn post_xml<Message>(outbound: &Outbound<Message>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(base64_decode(
        &outbound.raw_context().context,
    )?)?)
}

fn post_input<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn unsigned_response_fields(
    outbound: &Outbound<LogoutResponse>,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let xml = post_xml(outbound)?;
    let start = xml
        .find("<ds:Signature")
        .ok_or("signed LogoutResponse is missing ds:Signature")?;
    let end_rel = xml[start..]
        .find("</ds:Signature>")
        .ok_or("signed LogoutResponse has an unclosed ds:Signature")?;
    let end = start + end_rel + "</ds:Signature>".len();
    let unsigned = format!("{}{}", &xml[..start], &xml[end..]);
    assert!(!unsigned.contains("ds:Signature"));
    Ok(outbound
        .post_form()?
        .fields()
        .iter()
        .map(|field| {
            if field.name() == "SAMLResponse" {
                FormField::new("SAMLResponse", base64_encode(unsigned.as_bytes()))
            } else {
                field.clone()
            }
        })
        .collect())
}

#[test]
fn session_participant_generation_rules_sign_and_require_session_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::compatibility())?;
    let idp = idp(IDP_SLO_HTTPS, idp_with_slo_accept())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post().apply_single_logout_generation_rules(),
    )?;
    let xml = post_xml(&started.outbound)?;

    assert!(xml.contains("SessionIndex"));
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTPS}\"")));
    assert!(!xml.contains("NotOnOrAfter"));

    match sp.start_slo(
        &idp_descriptor,
        subject_without_session(),
        StartSlo::post().apply_single_logout_generation_rules(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("SessionIndex") => Ok(()),
        other => Err(format!("expected a SessionIndex rejection, got {other:?}").into()),
    }
}

#[test]
fn compatibility_session_participant_logout_stays_unsigned_without_session_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SP_SLO_HTTPS, SpValidationPolicy::compatibility())?;
    let identity_provider = idp(IDP_SLO_HTTP, IdpValidationPolicy::compatibility())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        subject_without_session(),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    let xml = post_xml(&started.outbound)?;

    assert!(!xml.contains("SessionIndex"));
    assert!(!xml.contains("ds:Signature"));
    assert!(!xml.contains("NotOnOrAfter"));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTP}\"")));

    let input = BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?);
    identity_provider.receive_slo(&sp_descriptor, input.clone(), validation())?;

    let rejecting = idp(IDP_SLO_HTTP, idp_with_slo_accept())?;
    match rejecting.receive_slo(&sp_descriptor, input, validation()) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!(
            "expected the accept combination to reject an unsigned LogoutRequest, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn http_logout_request_relaxes_transport_without_dropping_the_other_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::compatibility())?;
    let idp = idp(IDP_SLO_HTTP, idp_with_slo_accept())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post().apply_single_logout_generation_rules(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => {
            return Err(format!("expected an https rejection, got {other:?}").into());
        }
    }

    match sp.start_slo(
        &idp_descriptor,
        subject_without_session(),
        StartSlo::post()
            .apply_single_logout_generation_rules()
            .allow_http_single_logout(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("SessionIndex") => {}
        other => {
            return Err(format!("expected SessionIndex to stay required, got {other:?}").into());
        }
    }

    match sp.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post()
            .apply_single_logout_generation_rules()
            .allow_http_single_logout()
            .signing(LogoutSigning::DoNotSignForCompatibility),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("signature") => {}
        other => {
            return Err(format!("expected the signature to stay required, got {other:?}").into());
        }
    }

    let started = sp.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post()
            .apply_single_logout_generation_rules()
            .allow_http_single_logout(),
    )?;
    let xml = post_xml(&started.outbound)?;
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains("SessionIndex"));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTP}\"")));
    assert!(!xml.contains("NotOnOrAfter"));

    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .destination()
            .map(|endpoint| endpoint.as_str()),
        Some(IDP_SLO_HTTP)
    );
    Ok(())
}

#[test]
fn session_authority_keeps_expiration_and_does_not_gain_participant_duties(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTP, sp_with_slo_accept())?;
    let idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::compatibility())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(
        &sp_descriptor,
        subject_without_session(),
        StartSlo::post().apply_single_logout_generation_rules(),
    )?;
    let xml = post_xml(&started.outbound)?;
    assert!(xml.contains("NotOnOrAfter="));
    assert!(xml.contains("ds:Signature"));
    assert!(!xml.contains("SessionIndex"));
    assert!(xml.contains(&format!("Destination=\"{SP_SLO_HTTP}\"")));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));

    let compatible = idp.start_slo(
        &sp_descriptor,
        subject_without_session(),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    let compatible_xml = post_xml(&compatible.outbound)?;
    assert!(compatible_xml.contains("NotOnOrAfter="));
    assert!(!compatible_xml.contains("ds:Signature"));
    assert!(!compatible_xml.contains("SessionIndex"));

    let received = sp.receive_slo(
        &idp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .destination()
            .map(|endpoint| endpoint.as_str()),
        Some(SP_SLO_HTTP)
    );

    let participant_started =
        sp.start_slo(&idp_descriptor, subject_with_session()?, StartSlo::post())?;
    let received_by_authority = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_input(&participant_started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received_by_authority,
        RespondSlo::post().apply_single_logout_generation_rules(),
    )?;
    let response_xml = post_xml(&response)?;
    assert!(response_xml.contains("ds:Signature"));
    assert!(response_xml.contains(&format!("Destination=\"{SP_SLO_HTTP}\"")));

    let completed = sp.finish_slo(
        &idp_descriptor,
        &participant_started.pending,
        BrowserInput::<LogoutResponse>::post(post_input(&response)?),
        validation(),
    )?;
    assert_eq!(completed.peer_entity_id().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn session_participant_response_requires_https_unless_that_recommendation_is_relaxed(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, sp_with_slo_accept())?;
    let idp = idp(IDP_SLO_HTTP, idp_with_slo_accept())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(
        &sp_descriptor,
        subject_with_session()?,
        StartSlo::post().apply_single_logout_generation_rules(),
    )?;
    let received = sp.receive_slo(
        &idp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?),
        validation(),
    )?;

    match sp.respond_slo(
        &idp_descriptor,
        &received,
        RespondSlo::post().apply_single_logout_generation_rules(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => {
            return Err(format!("expected an https rejection, got {other:?}").into());
        }
    }

    let response = sp.respond_slo(
        &idp_descriptor,
        &received,
        RespondSlo::post()
            .apply_single_logout_generation_rules()
            .allow_http_single_logout(),
    )?;
    let xml = post_xml(&response)?;
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTP}\"")));

    let completed = idp.finish_slo(
        &sp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_input(&response)?),
        validation(),
    )?;
    assert_eq!(completed.peer_entity_id().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn finish_slo_requires_a_logout_response_signature_under_the_accept_combination(
) -> Result<(), Box<dyn std::error::Error>> {
    finish_rejects_unsigned_response(LocalRole::Sp)?;
    finish_rejects_unsigned_response(LocalRole::Idp)?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum LocalRole {
    Sp,
    Idp,
}

struct SignedLogoutExchange {
    response: Outbound<LogoutResponse>,
    pending: PendingLogoutRequest,
    service_provider: Saml<saml_rs::Sp>,
    identity_provider: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn finish_rejects_unsigned_response(role: LocalRole) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = signed_logout_response(role)?;
    let SignedLogoutExchange {
        response,
        pending,
        service_provider,
        identity_provider,
        sp_descriptor,
        idp_descriptor,
    } = exchange;
    let unsigned = unsigned_response_fields(&response)?;
    let accept_finish = match role {
        LocalRole::Sp => service_provider.finish_slo(
            &idp_descriptor,
            &pending,
            BrowserInput::<LogoutResponse>::post(unsigned.clone()),
            validation(),
        ),
        LocalRole::Idp => identity_provider.finish_slo(
            &sp_descriptor,
            &pending,
            BrowserInput::<LogoutResponse>::post(unsigned.clone()),
            validation(),
        ),
    };
    match accept_finish {
        Err(SamlError::SignatureMissing) => {}
        other => {
            return Err(format!("expected SignatureMissing for {role:?}, got {other:?}").into());
        }
    }

    let compatible_sp = sp(SP_SLO_HTTPS, SpValidationPolicy::compatibility())?;
    let compatible_idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::compatibility())?;
    let completed = match role {
        LocalRole::Sp => compatible_sp.finish_slo(
            &idp_descriptor,
            &pending,
            BrowserInput::<LogoutResponse>::post(unsigned),
            validation(),
        )?,
        LocalRole::Idp => compatible_idp.finish_slo(
            &sp_descriptor,
            &pending,
            BrowserInput::<LogoutResponse>::post(unsigned),
            validation(),
        )?,
    };
    assert!(completed.response().is_some());
    Ok(())
}

fn signed_logout_response(
    finishing_role: LocalRole,
) -> Result<SignedLogoutExchange, Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, sp_with_slo_accept())?;
    let idp = idp(IDP_SLO_HTTPS, idp_with_slo_accept())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let (response, pending) = match finishing_role {
        LocalRole::Sp => {
            let started = sp.start_slo(
                &idp_descriptor,
                subject_with_session()?,
                StartSlo::post().apply_single_logout_generation_rules(),
            )?;
            let received = idp.receive_slo(
                &sp_descriptor,
                BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?),
                validation(),
            )?;
            let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
            (response, started.pending)
        }
        LocalRole::Idp => {
            let started = idp.start_slo(
                &sp_descriptor,
                subject_without_session(),
                StartSlo::post().apply_single_logout_generation_rules(),
            )?;
            let received = sp.receive_slo(
                &idp_descriptor,
                BrowserInput::<LogoutRequest>::post(post_input(&started.outbound)?),
                validation(),
            )?;
            let response = sp.respond_slo(&idp_descriptor, &received, RespondSlo::post())?;
            (response, started.pending)
        }
    };
    Ok(SignedLogoutExchange {
        response,
        pending,
        service_provider: sp,
        identity_provider: idp,
        sp_descriptor,
        idp_descriptor,
    })
}

#[test]
fn logout_policy_defaults_follow_recommended() {
    assert_eq!(
        SpValidationPolicy::default().logout,
        LogoutPolicy::recommended()
    );
    assert_eq!(
        IdpValidationPolicy::default().logout,
        LogoutPolicy::recommended()
    );
    assert_eq!(LogoutPolicy::default(), LogoutPolicy::recommended());
    assert_eq!(
        SpValidationPolicy::recommended().logout,
        LogoutPolicy::recommended()
    );
    assert_eq!(
        IdpValidationPolicy::recommended().logout,
        LogoutPolicy::recommended()
    );
    assert_eq!(LogoutPolicy::recommended(), slo_accept_policy());
    assert_eq!(
        LogoutPolicy::compatibility().requests,
        LogoutSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        LogoutPolicy::compatibility().responses,
        LogoutSignaturePolicy::AllowUnsignedForCompatibility
    );
}
