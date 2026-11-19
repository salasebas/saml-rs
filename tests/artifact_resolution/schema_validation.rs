use super::*;

#[test]
fn schema_validator_rejects_artifact_soap_before_release() -> Result<(), Box<dyn std::error::Error>>
{
    fn reject(_: &str) -> Result<(), String> {
        Err("schema rejected artifact envelope".into())
    }
    let parties = parties_with(XmlPolicy {
        schema_validator: Some(reject),
        ..XmlPolicy::default()
    })?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let result = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    );
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected artifact envelope"),
        "expected schema rejection, got {result:?}"
    );
    let accepting = self::parties()?;
    let answer = accepting.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let result = resolution.finish(answer.response().envelope());
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected artifact envelope"),
        "expected schema rejection of the response, got {result:?}"
    );
    Ok(())
}
