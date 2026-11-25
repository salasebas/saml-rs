use super::*;
use saml_rs::tests::elliptic_curve_signatures::SIGNING_FIXTURES;
use saml_rs::{InMemoryReplayCache, SsoRequestBinding};

#[test]
fn elliptic_curve_signatures_round_trip_in_browser_sso() -> Result<(), Box<dyn std::error::Error>> {
    for fixture in SIGNING_FIXTURES {
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::post(SP_ACS_POST)?,
            )
            .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
            .credentials(fixture.credentials())
            .algorithms(fixture.algorithms())
            .validation(signing_sp_validation())
            .build()?,
        );
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
            .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
            .credentials(fixture.credentials())
            .algorithms(fixture.algorithms())
            .validation(signed_authn_request_idp_validation())
            .build()?,
        );
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let mut replay = InMemoryReplayCache::new();
        for (request_binding, start, response_binding, respond) in [
            (
                SsoRequestBinding::Post,
                StartSso::post(),
                SsoResponseBinding::Post,
                RespondSso::post(),
            ),
            (
                SsoRequestBinding::Redirect,
                StartSso::redirect(),
                SsoResponseBinding::Post,
                RespondSso::post(),
            ),
            (
                SsoRequestBinding::SimpleSign,
                StartSso::simple_sign(),
                SsoResponseBinding::SimpleSign,
                RespondSso::simple_sign(),
            ),
        ] {
            let started =
                sp.start_sso(&idp_descriptor, start.response_binding(response_binding))?;
            fixture.assert_signature(&started.outbound, "SAMLRequest")?;
            let request = match request_binding {
                SsoRequestBinding::Post => Inbound::post(post_fields(&started.outbound)?),
                SsoRequestBinding::Redirect => {
                    let url = Url::parse(started.outbound.redirect_url()?)?;
                    Inbound::redirect(url.query().ok_or("missing SAML query")?)
                }
                SsoRequestBinding::SimpleSign => {
                    Inbound::simple_sign(post_fields(&started.outbound)?)
                }
            };
            let received = idp.receive_sso(&sp_descriptor, request, validation())?;
            assert_eq!(received.message().id(), started.pending.request_id());
            let response = idp.respond_sso(
                &sp_descriptor,
                &received,
                SsoAssertion::new(principal()),
                respond.sign_response(),
            )?;
            fixture.assert_signature(&response, "SAMLResponse")?;
            let fields = post_fields(&response)?;
            let input = match response_binding {
                SsoResponseBinding::Post => Inbound::post(fields),
                SsoResponseBinding::SimpleSign => Inbound::simple_sign(fields),
                SsoResponseBinding::Artifact => return Err("unexpected artifact response".into()),
            };
            let session = sp.finish_sso(
                &idp_descriptor,
                &started.pending,
                input,
                validation_with_cache(&mut replay),
            )?;
            assert_eq!(session.name_id(), Some(&principal()));
            let verified: Vec<_> = session
                .verified_xml_signatures()
                .iter()
                .map(|signature| {
                    assert_eq!(signature.algorithm_uri(), fixture.uri);
                    signature.coverage()
                })
                .collect();
            assert!(verified.contains(&VerifiedXmlSignatureCoverage::ConsumedAssertion));
            if response_binding == SsoResponseBinding::Post {
                assert!(verified.contains(&VerifiedXmlSignatureCoverage::ResponseRoot));
                assert_eq!(session.binding_signature_algorithm_uri(), None);
            } else {
                assert_eq!(session.binding_signature_algorithm_uri(), Some(fixture.uri));
            }
        }
    }
    Ok(())
}
