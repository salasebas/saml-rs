use super::*;
use saml_rs::tests::elliptic_curve_signatures::SIGNING_FIXTURES;
use saml_rs::{AssertionSignaturePolicy, SpValidationPolicy, VerifiedXmlSignatureCoverage};
use std::time::SystemTime;

#[test]
fn elliptic_curve_signatures_round_trip_in_artifact_sso() -> Result<(), Box<dyn std::error::Error>>
{
    for fixture in SIGNING_FIXTURES {
        let (idp, sp) = artifact_config_builders(
            AcsEndpoint::post(SP_ACS_POST)?,
            AcsEndpoint::artifact(SP_ACS_ARTIFACT)?,
        )?;
        let parties = build_parties(
            idp.credentials(fixture.credentials())
                .algorithms(fixture.algorithms()),
            sp.credentials(fixture.credentials())
                .algorithms(fixture.algorithms())
                .validation(SpValidationPolicy {
                    assertion_signatures: AssertionSignaturePolicy::RequireSigned,
                    ..SpValidationPolicy::default()
                }),
        )?;
        let (pending, request) = requested(&parties, None)?;
        let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
        let response = parties.idp.respond_sso_artifact(
            &parties.sp_metadata,
            &request,
            SsoAssertion::new(principal(), SystemTime::now()),
            RespondSso::artifact(ArtifactDelivery::redirect(0)).sign_response(),
            &mut issued,
        )?;
        let session = follow_redirect_and_finish(&parties, &pending, &response, &mut issued)?;
        assert_eq!(session.name_id().ok_or("missing NameID")?.value(), USER);
        for coverage in [
            VerifiedXmlSignatureCoverage::ResponseRoot,
            VerifiedXmlSignatureCoverage::ConsumedAssertion,
        ] {
            assert!(session.verified_xml_signatures().iter().any(|signature| {
                signature.algorithm_uri() == fixture.uri && signature.coverage() == coverage
            }));
        }
    }
    Ok(())
}
