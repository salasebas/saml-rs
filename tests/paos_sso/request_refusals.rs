use super::*;
use saml_rs::{InMemoryReplayCache, MetadataLifetime, RequestAgePolicy, TimeWindowField};

#[test]
fn authenticated_age_and_replay_refusals_reach_the_sp_as_saml_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let endpoint = EndpointUrl::try_new(IDP_SOAP)?;
    let started = sp.start_paos_sso(&idp_descriptor, StartPaosSso::new(endpoint.clone()))?;
    let (client, request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let expired = SamlValidationContext::new(
        SystemTime::now() + Duration::from_secs(3600),
        ReplayPolicy::Disabled,
    )
    .with_authn_request_age(RequestAgePolicy::Bounded {
        max_age: Duration::from_secs(60),
    });
    let age_result = idp.receive_paos_sso(&sp_descriptor, &request, &endpoint, expired);

    let mut cache = InMemoryReplayCache::new();
    let receive = |cache: &mut InMemoryReplayCache| {
        let validation =
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
                .with_replay_retention(Duration::from_secs(300));
        idp.receive_paos_sso(&sp_descriptor, &request, &endpoint, validation)
    };
    receive(&mut cache)?;
    let replay_result = receive(&mut cache);

    let Err(SamlError::PaosRequestRefused {
        source, response, ..
    }) = age_result
    else {
        return Err("the signed AuthnRequest outside the age window must carry a refusal".into());
    };
    assert!(matches!(
        *source,
        SamlError::TimeWindowInvalid {
            field: TimeWindowField::AuthnRequestIssueInstant,
            ..
        }
    ));
    let Err(SamlError::PaosRequestRefused {
        source: replay_source,
        response: replay_response,
        ..
    }) = replay_result
    else {
        return Err("the repeated AuthnRequest must carry a refusal".into());
    };
    assert!(matches!(*replay_source, SamlError::ReplayDetected { .. }));

    for refusal in [response, replay_response] {
        assert_eq!(refusal.http_status(), 200);
        assert!(refusal.session_index().is_none());
        let to_sp = enhanced_client_takes_response(&client, refusal.envelope())?;
        match sp.finish_paos_sso(&idp_descriptor, &started.pending, &to_sp, validation()) {
            Err(SamlError::StatusNotSuccess { status, .. }) => {
                assert_eq!(status, Status::requester())
            }
            other => return Err(format!("expected a SAML Requester status, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn unsigned_requests_get_local_age_and_replay_errors() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let endpoint = EndpointUrl::try_new(IDP_SOAP)?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(endpoint.clone()).allow_unsigned_authn_request(),
    )?;
    let (_, request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let expired = SamlValidationContext::new(
        SystemTime::now() + Duration::from_secs(3600),
        ReplayPolicy::Disabled,
    )
    .with_authn_request_age(RequestAgePolicy::Bounded {
        max_age: Duration::from_secs(60),
    });
    assert!(matches!(
        idp.receive_paos_sso(&sp_descriptor, &request, &endpoint, expired),
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::AuthnRequestIssueInstant,
            ..
        })
    ));

    let mut cache = InMemoryReplayCache::new();
    let receive = |cache: &mut InMemoryReplayCache| {
        let validation =
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
                .with_replay_retention(Duration::from_secs(300));
        idp.receive_paos_sso(&sp_descriptor, &request, &endpoint, validation)
    };
    receive(&mut cache)?;
    assert!(matches!(
        receive(&mut cache),
        Err(SamlError::ReplayDetected { .. })
    ));
    Ok(())
}

#[test]
fn a_paos_refusal_uses_the_receive_clock_for_sp_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, idp, _, idp_descriptor) = parties()?;
    let valid_until = SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800);
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(credentials())
        .metadata_lifetime(MetadataLifetime::ValidUntil(valid_until))
        .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let endpoint = EndpointUrl::try_new(IDP_SOAP)?;
    let started = sp.start_paos_sso(&idp_descriptor, StartPaosSso::new(endpoint.clone()))?;
    let (_, request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let now = valid_until - Duration::from_secs(1);
    let validation = SamlValidationContext::new(now, ReplayPolicy::Disabled)
        .with_authn_request_age(RequestAgePolicy::Bounded {
            max_age: Duration::from_secs(60),
        });

    match idp.receive_paos_sso(&sp_descriptor, &request, &endpoint, validation) {
        Err(SamlError::PaosRequestRefused {
            source, response, ..
        }) => {
            assert!(matches!(
                *source,
                SamlError::TimeWindowInvalid {
                    field: TimeWindowField::AuthnRequestIssueInstant,
                    ..
                }
            ));
            assert_eq!(response.http_status(), 200);
            Ok(())
        }
        other => Err(format!("expected a PAOS age refusal, got {other:?}").into()),
    }
}
