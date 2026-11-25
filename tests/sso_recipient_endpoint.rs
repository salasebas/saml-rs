#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::{Duration, SystemTime};

use saml_rs::{
    AcsEndpoint, ArtifactDelivery, ArtifactResolutionService, AuthnRequest, DeliveredArtifact,
    EndpointUrl, EntityId, IdentityProvider, IdpConfig, IdpDescriptor, Inbound, IssuedArtifacts,
    MetadataTrustPolicy, NameId, NameIdFormat, Received, ReplayPolicy, RespondSso, SamlError,
    SamlValidationContext, ServiceProvider, SoapChannel, SpConfig, SpDescriptor, SsoAssertion,
    SsoEndpoint, SsoResponse, SsoResponseBinding, SsoSession, StartSso,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const ACS_A: &str = "https://sp.example.com/acs/a";
const ACS_B: &str = "https://sp.example.com/acs/b";
const OTHER_BINDING: &str = "https://sp.example.com/acs/other-binding";
const USER: &str = "user@example.com";
const BINDINGS: [SsoResponseBinding; 3] = [
    SsoResponseBinding::Post,
    SsoResponseBinding::SimpleSign,
    SsoResponseBinding::Artifact,
];

fn other_binding(binding: SsoResponseBinding) -> Result<SsoResponseBinding, SamlError> {
    Ok(match binding {
        SsoResponseBinding::Post => SsoResponseBinding::SimpleSign,
        SsoResponseBinding::SimpleSign | SsoResponseBinding::Artifact => SsoResponseBinding::Post,
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

fn sp(binding: SsoResponseBinding, default: &str) -> Result<ServiceProvider, SamlError> {
    sp_indexed(binding, default, [ACS_A, ACS_B])
}

fn sp_indexed(
    binding: SsoResponseBinding,
    default: &str,
    [first, second]: [&str; 2],
) -> Result<ServiceProvider, SamlError> {
    let acs = |index, location| -> Result<AcsEndpoint, SamlError> {
        let endpoint = AcsEndpoint::new(binding, EndpointUrl::try_new(location)?).with_index(index);
        Ok(if location == default {
            endpoint.with_default()
        } else {
            endpoint
        })
    };
    let other = AcsEndpoint::new(
        other_binding(binding)?,
        EndpointUrl::try_new(OTHER_BINDING)?,
    )
    .with_index(2);
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, acs(0, first)?)
            .acs_endpoints([acs(1, second)?, other])
            .credentials(signing_credentials())
            .build()?,
    ))
}

fn idp() -> Result<IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .credentials(signing_credentials())
        .build()?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn principal() -> NameId {
    NameId::new(USER).with_format(NameIdFormat::EmailAddress)
}

fn descriptors(
    sent_to: &ServiceProvider,
    idp: &IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sent_to.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
    ))
}

fn response_input(
    binding: SsoResponseBinding,
    receiver: &ServiceProvider,
    idp: &IdentityProvider,
    (sender_view, idp_descriptor): (&SpDescriptor, &IdpDescriptor),
    request: Option<&Received<AuthnRequest>>,
) -> Result<Inbound<SsoResponse>, Box<dyn std::error::Error>> {
    let assertion = SsoAssertion::new(principal());
    Ok(match binding {
        SsoResponseBinding::Post | SsoResponseBinding::SimpleSign => {
            let options = if binding == SsoResponseBinding::SimpleSign {
                RespondSso::simple_sign()
            } else {
                RespondSso::post()
            };
            let response = match request {
                Some(request) => idp.respond_sso(sender_view, request, assertion, options)?,
                None => idp.initiate_sso(sender_view, assertion, options)?,
            };
            let fields = response.post_form()?.fields().to_vec();
            if binding == SsoResponseBinding::SimpleSign {
                Inbound::simple_sign(fields)
            } else {
                Inbound::post(fields)
            }
        }
        SsoResponseBinding::Artifact => {
            let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60));
            let options = RespondSso::artifact(ArtifactDelivery::post_form(0));
            let response = match request {
                Some(request) => {
                    idp.respond_sso_artifact(sender_view, request, assertion, options, &mut issued)?
                }
                None => idp.initiate_sso_artifact(sender_view, assertion, options, &mut issued)?,
            };
            let delivered = DeliveredArtifact::from_form(response.post_form()?.fields())?;
            let resolution = receiver.resolve_artifact(
                idp_descriptor,
                delivered.artifact(),
                SoapChannel::mutually_authenticated_confidential(),
                SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
            )?;
            let answer = idp.answer_artifact_resolve(
                sender_view,
                resolution.request().envelope(),
                resolution.request().endpoint(),
                &mut issued,
                SoapChannel::mutually_authenticated_confidential(),
            )?;
            Inbound::artifact(delivered, resolution.finish(answer.response().envelope())?)
        }
        _ => return Err("unsupported response binding".into()),
    })
}

#[derive(Debug, Clone, Copy)]
enum Flow {
    Unsolicited,
    Solicited,
}

const FLOWS: [Flow; 2] = [Flow::Unsolicited, Flow::Solicited];

fn receive(
    flow: Flow,
    binding: SsoResponseBinding,
    sent_to: &str,
    validation: SamlValidationContext<'_>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    match flow {
        Flow::Unsolicited => accept(binding, sent_to, validation),
        Flow::Solicited => finish(binding, sent_to, validation),
    }
}

fn accept(
    binding: SsoResponseBinding,
    sent_to: &str,
    validation: SamlValidationContext<'_>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let receiver = sp(binding, ACS_A)?;
    let idp = idp()?;
    let (sender_view, idp_descriptor) = descriptors(&sp(binding, sent_to)?, &idp)?;
    let input = response_input(
        binding,
        &receiver,
        &idp,
        (&sender_view, &idp_descriptor),
        None,
    )?;
    Ok(receiver.accept_unsolicited_sso(&idp_descriptor, input, validation)?)
}

fn finish(
    binding: SsoResponseBinding,
    sent_to: &str,
    validation: SamlValidationContext<'_>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let acs_index = if sent_to == ACS_A { 0 } else { 1 };
    finish_with_idp_view(binding, acs_index, &sp(binding, ACS_A)?, validation)
}

fn finish_with_idp_view(
    binding: SsoResponseBinding,
    acs_index: u16,
    idp_view: &ServiceProvider,
    validation: SamlValidationContext<'_>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let receiver = sp(binding, ACS_A)?;
    let idp = idp()?;
    let (sender_view, idp_descriptor) = descriptors(idp_view, &idp)?;
    let started = receiver.start_sso(&idp_descriptor, StartSso::redirect().acs_index(acs_index))?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let request = idp.receive_sso(
        &sender_view,
        Inbound::redirect(url.query().unwrap_or_default()),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
    )?;
    let input = response_input(
        binding,
        &receiver,
        &idp,
        (&sender_view, &idp_descriptor),
        Some(&request),
    )?;
    Ok(receiver.finish_sso(&idp_descriptor, &started.pending, input, validation)?)
}

fn at(location: &str) -> Result<SamlValidationContext<'static>, SamlError> {
    Ok(validation().with_recipient_endpoint(EndpointUrl::try_new(location)?))
}

#[test]
fn a_response_to_the_supplied_non_default_consumer_is_accepted(
) -> Result<(), Box<dyn std::error::Error>> {
    for (flow, binding) in FLOWS
        .into_iter()
        .flat_map(|flow| BINDINGS.map(|binding| (flow, binding)))
    {
        let mut cache = saml_rs::InMemoryReplayCache::new();
        let policy = if binding == SsoResponseBinding::Post {
            ReplayPolicy::RequireCache(&mut cache)
        } else {
            ReplayPolicy::NoCache
        };
        let validation = SamlValidationContext::new(SystemTime::now(), policy)
            .with_recipient_endpoint(EndpointUrl::try_new(ACS_B)?);
        let session = receive(flow, binding, ACS_B, validation)?;
        assert_eq!(
            session.name_id().ok_or("missing NameID")?.value(),
            USER,
            "{flow:?} {binding:?}"
        );
    }
    Ok(())
}

#[test]
fn a_response_to_another_consumer_than_the_supplied_one_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for (flow, binding) in FLOWS
        .into_iter()
        .flat_map(|flow| BINDINGS.map(|binding| (flow, binding)))
    {
        let (want_expected, want_actual) = match flow {
            Flow::Unsolicited => (ACS_B, ACS_A),
            Flow::Solicited => (ACS_A, ACS_B),
        };
        match receive(flow, binding, ACS_A, at(ACS_B)?) {
            Err(error) => match error.downcast_ref::<SamlError>() {
                Some(SamlError::DestinationMismatch {
                    expected, actual, ..
                }) => {
                    assert_eq!(expected, want_expected, "{flow:?} {binding:?}");
                    assert_eq!(actual.as_deref(), Some(want_actual), "{flow:?} {binding:?}");
                }
                other => {
                    return Err(format!(
                        "{flow:?} {binding:?}: expected DestinationMismatch, got {other:?}"
                    )
                    .into())
                }
            },
            Ok(_) => {
                return Err(format!("{flow:?} {binding:?}: expected DestinationMismatch").into())
            }
        }
    }
    Ok(())
}

#[test]
fn a_supplied_consumer_not_published_for_the_binding_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for (flow, binding) in FLOWS
        .into_iter()
        .flat_map(|flow| BINDINGS.map(|binding| (flow, binding)))
    {
        match receive(flow, binding, ACS_A, at(OTHER_BINDING)?) {
            Err(error) => assert!(
                matches!(
                    error.downcast_ref::<SamlError>(),
                    Some(SamlError::RecipientEndpointNotPublished)
                ),
                "{flow:?} {binding:?}: {error:?}"
            ),
            Ok(_) => {
                return Err(
                    format!("{flow:?} {binding:?}: expected RecipientEndpointNotPublished").into(),
                )
            }
        }
    }
    Ok(())
}

#[test]
fn a_solicited_response_at_another_consumer_than_the_requested_one_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in BINDINGS {
        let stale_idp_view = sp_indexed(binding, ACS_B, [ACS_B, ACS_A])?;
        for (validation, received_at) in [(at(ACS_B)?, "supplied"), (validation(), "omitted")] {
            match finish_with_idp_view(binding, 0, &stale_idp_view, validation) {
                Err(error) => match error.downcast_ref::<SamlError>() {
                    Some(SamlError::DestinationMismatch {
                        expected, actual, ..
                    }) => {
                        assert_eq!(expected, ACS_A, "{binding:?} {received_at}");
                        assert_eq!(actual.as_deref(), Some(ACS_B), "{binding:?} {received_at}");
                    }
                    other => {
                        return Err(format!(
                            "{binding:?} {received_at}: expected DestinationMismatch, got {other:?}"
                        )
                        .into())
                    }
                },
                Ok(_) => {
                    return Err(
                        format!("{binding:?} {received_at}: expected DestinationMismatch").into(),
                    )
                }
            }
        }
    }
    Ok(())
}
