use super::*;

#[test]
fn signing_failure_leaves_the_artifact_available_to_retry() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let mut used = InMemoryReplayCache::new();
    let failed = parties.sp.resolve_artifact_with_signed_request(
        &parties.idp_metadata,
        &artifact,
        channel,
        single_use(&mut used),
    );
    if cfg!(crypto) {
        assert!(
            matches!(failed, Err(SamlError::MissingKey(ref key)) if key == "private_key"),
            "{failed:?}"
        );
    } else {
        assert!(
            matches!(failed, Err(SamlError::Unsupported(_))),
            "{failed:?}"
        );
    }

    let retry = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        single_use(&mut used),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        retry.request().envelope(),
        retry.request().endpoint(),
        &mut issued,
        channel,
    )?;
    assert!(retry
        .finish(answer.response().envelope())?
        .xml()
        .contains(WEB_SSO_MARKER));
    Ok(())
}
