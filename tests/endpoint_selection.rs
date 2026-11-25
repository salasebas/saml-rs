#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::Binding;
use saml_rs::{
    AcsEndpoint, ArtifactDelivery, ArtifactResolutionService, AuthnRequest, EndpointUrl, EntityId,
    FormField, IdentityProvider, IdpConfig, IdpDescriptor, Inbound, IssuedArtifacts,
    MetadataTrustPolicy, NameId, RelayState, ReplayPolicy, RespondSso, SamlError,
    SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SsoAssertion, SsoEndpoint,
    SsoOutcome, SsoResponseBinding, StartSso, Status,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const FIRST_ACS: &str = "https://sp.example.com/acs/first";
const DEFAULT_ACS: &str = "https://sp.example.com/acs/default";
const IDP_SSO_FIRST: &str = "https://idp.example.com/sso/first";
const IDP_SSO_SECOND: &str = "https://idp.example.com/sso/second";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn principal() -> NameId {
    NameId::new("alice@example.com")
}

fn sp_with_default_acs() -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(FIRST_ACS)?.with_index(0),
        )
        .acs_endpoint(AcsEndpoint::post(DEFAULT_ACS)?.with_index(1).with_default())
        .credentials(signing_credentials())
        .build()?,
    ))
}

fn idp_with_sso(first: &str, more: &[&str]) -> Result<saml_rs::IdentityProvider, SamlError> {
    let more = more
        .iter()
        .map(|url| SsoEndpoint::post(*url))
        .collect::<Result<Vec<_>, _>>()?;
    let builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?, SsoEndpoint::post(first)?)
        .sso_endpoints(more);
    Ok(IdentityProvider::new(
        builder.credentials(signing_credentials()).build()?,
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

fn authn_request(destination: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_authn" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>"#
    )
}

fn post_authn_request(xml: &str) -> Inbound<AuthnRequest> {
    Inbound::post(vec![FormField::new(
        "SAMLRequest",
        STANDARD.encode(xml.as_bytes()),
    )])
}

#[test]
fn default_assertion_consumer_service_is_selected_when_the_request_names_neither(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .acs_url()
            .map(saml_rs::EndpointUrl::as_str),
        Some(DEFAULT_ACS)
    );

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unspecified = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert_eq!(unspecified.message().acs_url(), None);
    assert_eq!(unspecified.message().acs_index(), None);
    let response = idp.respond_sso(
        &sp_descriptor,
        &unspecified,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);

    let cross_binding_sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(FIRST_ACS)?.with_index(0),
        )
        .acs_endpoint(
            AcsEndpoint::simple_sign(DEFAULT_ACS)?
                .with_index(1)
                .with_default(),
        )
        .credentials(signing_credentials())
        .build()?,
    );
    let (cross_binding_descriptor, _) = descriptors(&cross_binding_sp, &idp)?;
    let unspecified = idp.receive_sso(
        &cross_binding_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert_eq!(unspecified.message().protocol_binding(), None);
    assert!(matches!(
        idp.respond_sso(
            &cross_binding_descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    let response = idp.respond_sso(
        &cross_binding_descriptor,
        &unspecified,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);
    assert!(matches!(
        idp.initiate_sso(
            &cross_binding_descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    let unsolicited = idp.initiate_sso(
        &cross_binding_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unsupported_metadata = cross_binding_sp.metadata_xml().replace(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign",
        "urn:example:unsupported-binding",
    );
    let unsupported_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &unsupported_metadata,
        MetadataTrustPolicy::Unverified,
    )?;
    let unspecified = idp.receive_sso(
        &unsupported_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert!(matches!(
        idp.respond_sso(
            &unsupported_descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        idp.initiate_sso(
            &unsupported_descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));

    let saml2_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{FIRST_ACS}" index="0"/></SPSSODescriptor>"#
    );
    let saml1_role = r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="https://sp.example.com/saml1/acs" index="0" isDefault="true"/></SPSSODescriptor>"#;
    let second_saml2_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{DEFAULT_ACS}" index="1" isDefault="true"/></SPSSODescriptor>"#
    );
    for roles in [
        saml2_role.clone(),
        format!("{saml2_role}{saml1_role}"),
        format!("{saml1_role}{saml2_role}"),
        format!("{saml2_role}{second_saml2_role}"),
    ] {
        let metadata = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}">{roles}</EntityDescriptor>"#
        );
        let descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::Unverified,
        )?;
        let unspecified = idp.receive_sso(
            &descriptor,
            post_authn_request(&authn_request(IDP_SSO_FIRST)),
            validation(),
        )?;
        assert_eq!(unspecified.message().acs_url(), None);
        assert_eq!(unspecified.message().acs_index(), None);
        let response = idp.respond_sso(
            &descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post(),
        )?;
        assert_eq!(response.post_form()?.action().as_str(), FIRST_ACS);
        let unsolicited = idp.initiate_sso(
            &descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post(),
        )?;
        assert_eq!(unsolicited.post_form()?.action().as_str(), FIRST_ACS);
    }
    Ok(())
}

#[test]
fn protocol_binding_alone_uses_the_binding_default() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_FIRST)?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .credentials(signing_credentials())
        .build()?,
    );
    for binding in [
        SsoResponseBinding::Post,
        SsoResponseBinding::SimpleSign,
        SsoResponseBinding::Artifact,
    ] {
        let global_binding = match binding {
            SsoResponseBinding::Post => SsoResponseBinding::SimpleSign,
            SsoResponseBinding::SimpleSign | SsoResponseBinding::Artifact => {
                SsoResponseBinding::Post
            }
            _ => return Err("unsupported response binding".into()),
        };
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::new(global_binding, EndpointUrl::try_new(DEFAULT_ACS)?)
                    .with_index(0)
                    .with_default(),
            )
            .acs_endpoint(AcsEndpoint::new(binding, EndpointUrl::try_new(FIRST_ACS)?).with_index(1))
            .credentials(signing_credentials())
            .build()?,
        );
        let (sp_descriptor, _) = descriptors(&sp, &idp)?;
        let xml = authn_request(IDP_SSO_FIRST).replace(
            " Version=",
            &format!(
                " ProtocolBinding=\"{}\" Version=",
                Binding::from(binding).urn()
            ),
        );
        let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
        assert_eq!(request.message().acs_url(), None);
        assert_eq!(request.message().acs_index(), None);
        assert_eq!(request.message().protocol_binding(), Some(binding));
        match binding {
            SsoResponseBinding::Post | SsoResponseBinding::SimpleSign => {
                let options = if binding == SsoResponseBinding::Post {
                    RespondSso::post()
                } else {
                    RespondSso::simple_sign()
                };
                let response = idp.respond_sso(
                    &sp_descriptor,
                    &request,
                    SsoAssertion::new(principal()),
                    options,
                )?;
                assert_eq!(response.post_form()?.action().as_str(), FIRST_ACS);
            }
            SsoResponseBinding::Artifact => {
                let mut issued = IssuedArtifacts::expire_after(std::time::Duration::from_secs(60));
                let response = idp.respond_sso_artifact(
                    &sp_descriptor,
                    &request,
                    SsoAssertion::new(principal()),
                    RespondSso::artifact(ArtifactDelivery::redirect(0)),
                    &mut issued,
                )?;
                assert_eq!(
                    url::Url::parse(response.redirect_url()?)?.path(),
                    "/acs/first"
                );
            }
            _ => return Err("unsupported response binding".into()),
        }
    }
    Ok(())
}

#[test]
fn a_stale_acs_index_allows_a_correlated_error_at_the_current_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let updated_sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(DEFAULT_ACS)?.with_index(7).with_default(),
        )
        .credentials(signing_credentials())
        .build()?,
    );
    let (updated_descriptor, _) = descriptors(&updated_sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .acs_index(1)
            .relay_state(RelayState::try_new("login-42")?),
    )?;
    let received = idp.receive_sso(
        &updated_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert!(matches!(
        idp.respond_sso(
            &updated_descriptor,
            &received,
            SsoAssertion::new(principal()),
            RespondSso::post(),
        ),
        Err(SamlError::MissingMetadata(_))
    ));

    let status = Status::requester();
    assert!(matches!(
        idp.respond_sso(
            &updated_descriptor,
            &received,
            SsoOutcome::Failure(status.clone()),
            RespondSso::simple_sign(),
        ),
        Err(SamlError::Invalid(_))
    ));
    let options = RespondSso::post().status_message("The ACS index is no longer published.");
    let response = idp.respond_sso(
        &updated_descriptor,
        &received,
        SsoOutcome::Failure(status.clone()),
        options,
    )?;
    let form = response.post_form()?;
    assert_eq!(form.action().as_str(), DEFAULT_ACS);
    assert_eq!(form.value("RelayState"), Some("login-42"));
    let xml = STANDARD.decode(form.value("SAMLResponse").ok_or("missing SAMLResponse")?)?;
    let document = roxmltree::Document::parse(std::str::from_utf8(&xml)?)?;
    let root = document.root_element();
    assert_eq!(root.attribute("Destination"), Some(DEFAULT_ACS));
    assert_eq!(
        root.attribute("InResponseTo"),
        Some(started.pending.request_id().as_str())
    );
    assert!(!root
        .children()
        .any(|child| matches!(child.tag_name().name(), "Assertion" | "EncryptedAssertion")));
    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(form.fields().to_vec()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess {
            status: actual,
            status_message,
            ..
        }) => {
            assert_eq!(actual, status);
            assert_eq!(
                status_message.as_ref().map(saml_rs::StatusMessage::as_str),
                Some("The ACS index is no longer published.")
            );
        }
        other => {
            return Err(format!("expected a correlated requester error, got {other:?}").into())
        }
    }
    Ok(())
}

#[test]
fn conflicting_request_acs_selectors_are_not_answered() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    for (selector, options, expected) in [
        (
            format!(
                " AssertionConsumerServiceURL=\"{DEFAULT_ACS}\" AssertionConsumerServiceIndex=\"0\""
            ),
            RespondSso::post(),
            "AuthnRequest must not specify both ACS URL and ACS index",
        ),
        (
            " AssertionConsumerServiceIndex=\"0\"".to_string(),
            RespondSso::simple_sign(),
            "response binding conflicts with AuthnRequest ACS index",
        ),
    ] {
        let xml =
            authn_request(IDP_SSO_FIRST).replace(" Version=", &format!("{selector} Version="));
        let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
        match idp.respond_sso(
            &sp_descriptor,
            &request,
            SsoAssertion::new(principal()),
            options,
        ) {
            Err(SamlError::Invalid(message)) => assert_eq!(message, expected),
            other => return Err(format!("expected Invalid({expected}), got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn a_response_is_not_sent_to_an_unpublished_request_acs() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let unpublished = "https://sp.example.com/acs/unpublished";
    let xml = authn_request(IDP_SSO_FIRST).replace(
        " Version=",
        &format!(" AssertionConsumerServiceURL=\"{unpublished}\" Version="),
    );
    let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
    match idp.respond_sso(
        &sp_descriptor,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    ) {
        Err(SamlError::DestinationMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, unpublished);
            assert_eq!(actual.as_deref(), Some(DEFAULT_ACS));
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn sso_destination_matches_the_actual_published_receiving_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[IDP_SSO_SECOND])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let accepted = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_SECOND)?),
    )?;
    assert_eq!(
        accepted
            .message()
            .destination()
            .map(saml_rs::EndpointUrl::as_str),
        Some(IDP_SSO_SECOND)
    );

    let rejected = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request("https://idp.example.com/sso/unknown")),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_FIRST)?),
    );
    match rejected {
        Err(SamlError::DestinationMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, IDP_SSO_FIRST);
            assert_eq!(
                actual.as_deref(),
                Some("https://idp.example.com/sso/unknown")
            );
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }

    let wrong_handler = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_FIRST)?),
    );
    assert!(matches!(
        wrong_handler,
        Err(SamlError::DestinationMismatch { .. })
    ));

    let ambiguous = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation(),
    );
    assert!(matches!(
        ambiguous,
        Err(SamlError::RecipientEndpointAmbiguous)
    ));
    Ok(())
}

const SECOND_ROLE_ACS: &str = "https://sp.example.com/acs/second-role";

fn sp_with_roles(roles: &[String]) -> Result<SpDescriptor, SamlError> {
    let roles: String = roles
        .iter()
        .map(|endpoints| {
            format!(
                r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{endpoints}</SPSSODescriptor>"#
            )
        })
        .collect();
    SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}">{roles}</EntityDescriptor>"#
        ),
        MetadataTrustPolicy::Unverified,
    )
}

fn acs(binding: SsoResponseBinding, location: &str, index: u16, is_default: &str) -> String {
    format!(
        r#"<AssertionConsumerService Binding="{}" Location="{location}" index="{index}"{is_default}/>"#,
        Binding::from(binding).urn()
    )
}

fn respond_to_request(
    sp: &SpDescriptor,
    selector: &str,
    options: RespondSso,
) -> Result<Result<String, SamlError>, Box<dyn std::error::Error>> {
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let xml = authn_request(IDP_SSO_FIRST).replace(" Version=", &format!("{selector} Version="));
    let request = idp.receive_sso(sp, post_authn_request(&xml), validation())?;
    Ok(idp
        .respond_sso(sp, &request, SsoAssertion::new(principal()), options)
        .and_then(|response| Ok(response.post_form()?.action().as_str().to_owned())))
}

#[test]
fn an_acs_index_is_unique_only_within_its_sp_role() -> Result<(), Box<dyn std::error::Error>> {
    let first_role = acs(SsoResponseBinding::Post, FIRST_ACS, 0, "");
    let second_role = format!(
        "{}{}",
        acs(SsoResponseBinding::Post, DEFAULT_ACS, 0, ""),
        acs(SsoResponseBinding::Post, SECOND_ROLE_ACS, 1, "")
    );
    let sp = sp_with_roles(&[first_role.clone(), second_role.clone()])?;
    let index = |index: u16| format!(" AssertionConsumerServiceIndex=\"{index}\"");

    assert_eq!(
        respond_to_request(&sp, &index(1), RespondSso::post())??,
        SECOND_ROLE_ACS
    );
    match respond_to_request(&sp, &index(0), RespondSso::post())? {
        Err(SamlError::Invalid(message)) => assert_eq!(
            message,
            "AssertionConsumerService index 0 is published by more than one SPSSODescriptor"
        ),
        other => return Err(format!("expected a refused shared index, got {other:?}").into()),
    }

    let shared_with_paos = sp_with_roles(&[
        format!(
            r#"{first_role}<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://sp.example.com/ecp" index="1"/>"#
        ),
        second_role.clone(),
    ])?;
    match respond_to_request(&shared_with_paos, &index(1), RespondSso::post())? {
        Err(SamlError::Invalid(message)) => assert_eq!(
            message,
            "AssertionConsumerService index 1 is published by more than one SPSSODescriptor"
        ),
        other => return Err(format!("expected a refused shared index, got {other:?}").into()),
    }

    let repeated_in_one_role = sp_with_roles(&[
        first_role,
        format!(
            "{second_role}{}",
            acs(
                SsoResponseBinding::Post,
                "https://sp.example.com/acs/again",
                1,
                ""
            )
        ),
    ])?;
    match respond_to_request(&repeated_in_one_role, &index(1), RespondSso::post())? {
        Err(SamlError::Invalid(message)) => {
            assert_eq!(message, "duplicate AssertionConsumerService index 1");
        }
        other => return Err(format!("expected a duplicate index error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_protocol_binding_default_comes_from_the_first_sp_role_with_that_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_roles(&[
        acs(SsoResponseBinding::Post, FIRST_ACS, 0, ""),
        format!(
            "{}{}",
            acs(
                SsoResponseBinding::Post,
                DEFAULT_ACS,
                0,
                r#" isDefault="true""#
            ),
            acs(SsoResponseBinding::SimpleSign, SECOND_ROLE_ACS, 1, "")
        ),
    ])?;
    let protocol_binding = |binding: SsoResponseBinding| {
        format!(" ProtocolBinding=\"{}\"", Binding::from(binding).urn())
    };

    assert_eq!(
        respond_to_request(
            &sp,
            &protocol_binding(SsoResponseBinding::Post),
            RespondSso::post()
        )??,
        FIRST_ACS
    );
    assert_eq!(
        respond_to_request(
            &sp,
            &protocol_binding(SsoResponseBinding::SimpleSign),
            RespondSso::simple_sign()
        )??,
        SECOND_ROLE_ACS
    );
    Ok(())
}

#[test]
fn response_goes_to_an_http_assertion_consumer_service_only_under_allow_http(
) -> Result<(), Box<dyn std::error::Error>> {
    const HTTP_ACS: &str = "http://sp.example.com/acs";
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(HTTP_ACS)?,
        )
        .credentials(signing_credentials())
        .build()?,
    );
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    for outcome in [
        SsoOutcome::from(SsoAssertion::new(principal())),
        SsoOutcome::Failure(Status::responder()),
    ] {
        let refused = idp.initiate_sso(&sp_descriptor, outcome.clone(), RespondSso::post());
        assert!(
            matches!(&refused, Err(SamlError::ProtocolProfile(message)) if message.contains("allow_http")),
            "{refused:?}"
        );
        let allowed = idp.initiate_sso(&sp_descriptor, outcome, RespondSso::post().allow_http())?;
        assert_eq!(allowed.post_form()?.action().as_str(), HTTP_ACS);
    }
    Ok(())
}
