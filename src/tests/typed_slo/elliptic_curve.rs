use super::*;
use saml_rs::tests::elliptic_curve_signatures::SIGNING_FIXTURES;

#[test]
fn elliptic_curve_signatures_round_trip_in_both_logout_directions(
) -> Result<(), Box<dyn std::error::Error>> {
    for fixture in SIGNING_FIXTURES {
        let sp = ServiceProvider::new(
            sp_config_builder(signing_sp_validation())?
                .credentials(fixture.credentials())
                .algorithms(fixture.algorithms())
                .build()?,
        );
        let idp = IdentityProvider::new(
            idp_config_builder(signed_authn_request_idp_validation())?
                .credentials(fixture.credentials())
                .algorithms(fixture.algorithms())
                .build()?,
        );
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        for binding in LOGOUT_BINDINGS_WITH_SOAP {
            let started =
                sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
            fixture.assert_signature(&started.outbound, "SAMLRequest")?;
            let received = idp.receive_slo(
                &sp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation(),
            )?;
            let response = idp.respond_slo(
                &sp_descriptor,
                &received,
                &Status::success(),
                respond_slo_for_binding(binding),
            )?;
            fixture.assert_signature(&response, "SAMLResponse")?;
            let completed = sp.finish_slo(
                &idp_descriptor,
                &started.pending,
                logout_response_input(&response, binding)?,
                validation(),
            )?;
            assert_eq!(
                completed.response().in_response_to(),
                Some(started.pending.request_id())
            );

            let started =
                idp.start_slo(&sp_descriptor, subject()?, start_slo_for_binding(binding))?;
            fixture.assert_signature(&started.outbound, "SAMLRequest")?;
            let received = sp.receive_slo(
                &idp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation(),
            )?;
            let response = sp.respond_slo(
                &idp_descriptor,
                &received,
                &Status::success(),
                respond_slo_for_binding(binding),
            )?;
            fixture.assert_signature(&response, "SAMLResponse")?;
            let completed = idp.finish_slo(
                &sp_descriptor,
                &started.pending,
                logout_response_input(&response, binding)?,
                validation(),
            )?;
            assert_eq!(
                completed.response().in_response_to(),
                Some(started.pending.request_id())
            );
        }
    }
    Ok(())
}
