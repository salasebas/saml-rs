//! `accept_unsolicited_sso` compares `Destination` and the bearer `Recipient`
//! with the assertion consumer named by
//! `SamlValidationContext::with_recipient_endpoint`.
//!
//! The service provider publishes two assertion consumers for each binding:
//! `/acs/a`, its default, and `/acs/b`. The identity provider reads metadata
//! that marks `/acs/b` default, so its unsolicited responses go there.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::{Duration, SystemTime};

use saml_rs::{
    AcsEndpoint, ArtifactDelivery, ArtifactDereference, ArtifactResolutionService, ArtifactUses,
    BrowserInput, DeliveredArtifact, EndpointUrl, EntityId, Idp, IdpConfig, IdpDescriptor,
    IssuedArtifacts, MetadataTrustPolicy, NameId, ReplayPolicy, RespondSso, Saml, SamlError,
    SamlValidationContext, SoapChannel, Sp, SpConfig, SpDescriptor, SsoEndpoint, SsoResponse,
    SsoResponseBinding, SsoSession, Subject,
};

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

/// The binding of the consumer published at [`OTHER_BINDING`].
fn other_binding(binding: SsoResponseBinding) -> SsoResponseBinding {
    match binding {
        SsoResponseBinding::Post => SsoResponseBinding::SimpleSign,
        SsoResponseBinding::SimpleSign | SsoResponseBinding::Artifact => SsoResponseBinding::Post,
    }
}

/// A service provider with `/acs/a` and `/acs/b` for `binding`, the one at
/// `default` marked default, and [`OTHER_BINDING`] for another binding.
fn sp(binding: SsoResponseBinding, default: &str) -> Result<Saml<Sp>, SamlError> {
    let mut builder = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?);
    for (index, location) in [(0, ACS_A), (1, ACS_B)] {
        let endpoint = AcsEndpoint::new(binding, EndpointUrl::try_new(location)?).with_index(index);
        builder = builder.acs_endpoint(if location == default {
            endpoint.mark_default()
        } else {
            endpoint
        });
    }
    let other = AcsEndpoint::new(other_binding(binding), EndpointUrl::try_new(OTHER_BINDING)?)
        .with_index(2);
    Saml::sp(
        builder
            .acs_endpoint(other)
            .credentials(signing_credentials())
            .build()?,
    )
}

fn idp() -> Result<Saml<Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new("https://idp.example.com/artifact")?,
            ))
            .credentials(signing_credentials())
            .build()?,
    )
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(NameId::new(USER, None), Vec::new())
}

/// The receiving service provider, whose default is `/acs/a`, accepts an
/// unsolicited response the identity provider sent to `sent_to`.
fn accept(
    binding: SsoResponseBinding,
    sent_to: &str,
    validation: SamlValidationContext<'_>,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let receiver = sp(binding, ACS_A)?;
    let sender_view = SpDescriptor::from_metadata_xml(
        sp(binding, sent_to)?.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp = idp()?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let input = match binding {
        SsoResponseBinding::Post | SsoResponseBinding::SimpleSign => {
            let options = match binding {
                SsoResponseBinding::SimpleSign => RespondSso::simple_sign(),
                SsoResponseBinding::Post | SsoResponseBinding::Artifact => RespondSso::post(),
            };
            let response = idp.initiate_sso(&sender_view, subject(), options)?;
            let fields = response.post_form()?.fields().to_vec();
            match binding {
                SsoResponseBinding::SimpleSign => BrowserInput::<SsoResponse>::simple_sign(fields),
                SsoResponseBinding::Post | SsoResponseBinding::Artifact => {
                    BrowserInput::<SsoResponse>::post(fields)
                }
            }
        }
        SsoResponseBinding::Artifact => {
            let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60));
            let response = idp.initiate_sso_artifact(
                &sender_view,
                subject(),
                RespondSso::artifact(ArtifactDelivery::post_form(0)),
                &mut issued,
            )?;
            let delivered = DeliveredArtifact::from_form(response.post_form()?.fields())?;
            let resolution = receiver.resolve_artifact(
                &idp_descriptor,
                delivered.artifact(),
                ArtifactDereference::web_browser_sso(
                    SoapChannel::mutually_authenticated_confidential(),
                )?,
                &mut ArtifactUses::enforce_single_use(Duration::from_secs(600)),
            )?;
            let answer = idp.answer_artifact_resolve(
                &sender_view,
                resolution.request().envelope(),
                &mut issued,
                SoapChannel::mutually_authenticated_confidential(),
            )?;
            BrowserInput::<SsoResponse>::artifact(delivered, resolution.finish(answer.envelope())?)
        }
    };
    Ok(receiver.accept_unsolicited_sso(&idp_descriptor, input, validation)?)
}

fn at(location: &str) -> Result<SamlValidationContext<'static>, SamlError> {
    Ok(validation().with_recipient_endpoint(EndpointUrl::try_new(location)?))
}

#[test]
fn a_response_to_the_supplied_non_default_consumer_is_accepted(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in BINDINGS {
        let session = accept(binding, ACS_B, at(ACS_B)?)?;
        assert_eq!(session.name_id().value(), USER, "{binding:?}");
    }
    Ok(())
}

#[test]
fn a_response_to_another_consumer_than_the_supplied_one_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in BINDINGS {
        match accept(binding, ACS_A, at(ACS_B)?) {
            Err(error) => match error.downcast_ref::<SamlError>() {
                Some(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, ACS_B, "{binding:?}");
                    assert_eq!(actual.as_deref(), Some(ACS_A), "{binding:?}");
                }
                other => {
                    return Err(
                        format!("{binding:?}: expected DestinationMismatch, got {other:?}").into(),
                    )
                }
            },
            Ok(_) => return Err(format!("{binding:?}: expected DestinationMismatch").into()),
        }
    }
    Ok(())
}

#[test]
fn a_supplied_consumer_not_published_for_the_binding_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in BINDINGS {
        match accept(binding, ACS_A, at(OTHER_BINDING)?) {
            Err(error) => assert!(
                matches!(
                    error.downcast_ref::<SamlError>(),
                    Some(SamlError::Invalid(_))
                ),
                "{binding:?}: {error:?}"
            ),
            Ok(_) => return Err(format!("{binding:?}: expected Invalid").into()),
        }
    }
    Ok(())
}
