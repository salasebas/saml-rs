use saml_rs::{AnsweredArtifact, ArtifactRelease, EndpointUrl, IssuedArtifacts};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";

fn status_xml(top_level: &str) -> String {
    format!(r#"<samlp:Status><samlp:StatusCode Value="{top_level}"/></samlp:Status>"#)
}

fn request_id(envelope: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let start = envelope.find(" ID=\"").ok_or("the request has no ID")? + 5;
    let end = envelope[start..]
        .find('"')
        .ok_or("the request ID has no closing quote")?;
    Ok(&envelope[start..start + end])
}

fn answer(
    parties: &Parties,
    envelope: &str,
    issued: &mut IssuedArtifacts,
) -> Result<AnsweredArtifact, Box<dyn std::error::Error>> {
    Ok(parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        envelope,
        &EndpointUrl::try_new(RESOLUTION_URL)?,
        issued,
        confidential(),
    )?)
}

fn assert_refused(
    answered: &AnsweredArtifact,
    release: ArtifactRelease,
    top_level: &str,
    in_response_to: Option<&str>,
    case: &str,
) {
    let envelope = answered.response().envelope();
    assert_eq!(answered.release(), release, "{case}");
    assert!(answered.error().is_some(), "{case}");
    assert!(
        envelope.contains(&status_xml(top_level)),
        "{case}: {envelope}"
    );
    assert!(!envelope.contains(WEB_SSO_MARKER), "{case}: {envelope}");
    match in_response_to {
        Some(id) => assert!(
            envelope.contains(&format!(r#"InResponseTo="{id}""#)),
            "{case}: {envelope}"
        ),
        None => assert!(!envelope.contains("InResponseTo="), "{case}: {envelope}"),
    }
}

#[test]
fn a_malformed_artifact_resolve_is_answered_with_requester_and_stays_outstanding() -> TestResult {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        without_replay_cache(),
    )?;
    let request = resolution.request().envelope();
    let id = request_id(request)?;
    let artifact_element = format!("<samlp:Artifact>{}</samlp:Artifact>", artifact.as_str());
    assert!(request.contains(&artifact_element));
    let cases = [
        ("no Artifact", request.replacen(&artifact_element, "", 1), Some(id)),
        (
            "a second Artifact",
            request.replacen(
                "</samlp:Artifact>",
                r#"</samlp:Artifact><other:Artifact xmlns:other="urn:example:other">extra</other:Artifact>"#,
                1,
            ),
            Some(id),
        ),
        (
            "a second Issuer",
            request.replacen(
                "</saml:Issuer>",
                &format!("</saml:Issuer><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
                1,
            ),
            Some(id),
        ),
        ("no ID", remove_attribute(request, "ID")?, None),
        (
            "an ID that is not an NCName",
            request.replacen(" ID=\"_", " ID=\"1bad:_", 1),
            None,
        ),
        ("no Version", remove_attribute(request, "Version")?, Some(id)),
        (
            "a Version that is not major.minor",
            request.replacen(r#"Version="2.0""#, r#"Version="2""#, 1),
            Some(id),
        ),
        (
            "no IssueInstant",
            remove_attribute(request, "IssueInstant")?,
            Some(id),
        ),
    ];
    for (case, malformed, in_response_to) in cases {
        assert_ne!(malformed, request, "{case}");
        let refused = answer(&parties, &malformed, &mut issued)?;
        assert_refused(
            &refused,
            ArtifactRelease::MalformedRequest,
            REQUESTER,
            in_response_to,
            case,
        );
    }

    let accepted = answer(&parties, request, &mut issued)?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    assert!(resolution
        .finish(accepted.response().envelope())?
        .xml()
        .contains(WEB_SSO_MARKER));
    Ok(())
}

#[cfg(not(crypto))]
#[test]
fn a_signed_artifact_resolve_without_a_crypto_provider_is_answered_with_responder() -> TestResult {
    const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        without_replay_cache(),
    )?;
    let with_signature = |envelope: &str| {
        envelope.replacen(
            "</saml:Issuer>",
            r#"</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
            1,
        )
    };
    let request = resolution.request().envelope();
    let unverifiable = answer(&parties, &with_signature(request), &mut issued)?;
    assert_refused(
        &unverifiable,
        ArtifactRelease::VerificationUnavailable,
        RESPONDER,
        Some(request_id(request)?),
        "signed request",
    );
    assert!(
        matches!(unverifiable.error(), Some(SamlError::Unsupported(_))),
        "{unverifiable:?}"
    );
    let later_major = with_signature(&request.replacen(r#"Version="2.0""#, r#"Version="3.0""#, 1));
    let result = answer(&parties, &later_major, &mut issued);
    assert!(
        matches!(&result, Err(error) if matches!(error.downcast_ref::<SamlError>(), Some(SamlError::Unsupported(_)))),
        "{result:?}"
    );

    let answer = answer(&parties, request, &mut issued)?;
    let envelope = answer.response().envelope();
    let result = resolution.finish(&with_signature(envelope));
    assert!(
        matches!(result, Err(SamlError::Unsupported(_))),
        "{result:?}"
    );
    assert!(resolution.finish(envelope)?.xml().contains(WEB_SSO_MARKER));
    Ok(())
}
