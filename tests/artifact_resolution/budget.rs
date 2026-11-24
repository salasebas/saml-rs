use super::*;
use saml_rs::{ArtifactChannelRequirement, ArtifactStore, IssuedArtifact, ResourceLimit};

const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const ISSUE_INSTANT: &str = "2024-01-01T00:00:00Z";
const RESPONSE_ID: &str = "_0123456789abcdef0123456789abcdef01234567";

pub(super) fn response_envelope_overhead(request_id: &str) -> usize {
    format!(
        concat!(
            r#"<soap:Envelope xmlns:soap="{0}"><soap:Body>"#,
            r#"<samlp:ArtifactResponse xmlns:samlp="{1}" xmlns:saml="{2}" ID="{3}" Version="2.0" IssueInstant="{4}" InResponseTo="{5}">"#,
            r#"<saml:Issuer>{6}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{7}"/></samlp:Status>"#,
            "</samlp:ArtifactResponse></soap:Body></soap:Envelope>",
        ),
        SOAP, PROTOCOL, ASSERTION, RESPONSE_ID, ISSUE_INSTANT, request_id, IDP_ENTITY_ID, SUCCESS,
    ).len()
}

fn response_at_envelope_size(size: usize, request_id: &str) -> Option<String> {
    let protocol_start = format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="{0}" xmlns:saml="{1}" ID="_login" Version="2.0" IssueInstant="{2}">"#,
            r#"<samlp:Status><samlp:StatusCode Value="{3}"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="{2}">"#,
            r#"<saml:Issuer>{4}</saml:Issuer><saml:AttributeStatement>"#,
            r#"<saml:Attribute Name="entitlements"><saml:AttributeValue>"#,
        ),
        PROTOCOL, ASSERTION, ISSUE_INSTANT, SUCCESS, IDP_ENTITY_ID,
    );
    let protocol_end = concat!(
        "</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>",
        "</saml:Assertion></samlp:Response>",
    );
    let text_bytes = size.checked_sub(
        response_envelope_overhead(request_id) + protocol_start.len() + protocol_end.len(),
    )?;
    Some(format!(
        "{protocol_start}{}{protocol_end}",
        "a".repeat(text_bytes)
    ))
}

fn resolve_with_id(artifact: &Artifact, request_id: &str) -> String {
    format!(
        concat!(
            r#"<soap:Envelope xmlns:soap="{0}"><soap:Body>"#,
            r#"<samlp:ArtifactResolve xmlns:samlp="{1}" xmlns:saml="{2}" ID="{3}" Version="2.0" IssueInstant="{4}" Destination="{5}">"#,
            r#"<saml:Issuer>{6}</saml:Issuer><samlp:Artifact>{7}</samlp:Artifact>"#,
            "</samlp:ArtifactResolve></soap:Body></soap:Envelope>",
        ),
        SOAP,
        PROTOCOL,
        ASSERTION,
        request_id,
        ISSUE_INSTANT,
        RESOLUTION_URL,
        SP_ENTITY_ID,
        artifact.as_str(),
    )
}

#[test]
fn issuance_reserves_the_complete_soap_response_budget() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let limits = XmlLimits::default();
    let request_id = "_".repeat(limits.max_attribute_value_bytes);
    let at_limit = response_at_envelope_size(limits.max_bytes, &request_id)
        .ok_or("budget cannot hold the envelope")?;
    let over_limit = response_at_envelope_size(limits.max_bytes + 1, &request_id)
        .ok_or("budget cannot hold the envelope")?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);

    let too_large = issue(&parties, &over_limit, &mut issued);
    assert!(
        matches!(too_large, Err(SamlError::LimitExceeded { limit: ResourceLimit::XmlBytes, maximum, .. }) if maximum == limits.max_bytes),
        "expected issuance to reject an over-budget envelope, got {too_large:?}"
    );
    let artifact = issue(&parties, &at_limit, &mut issued)?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &resolve_with_id(&artifact, &request_id),
        &EndpointUrl::try_new(RESOLUTION_URL)?,
        &mut issued,
        confidential(),
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    assert_eq!(answer.response().envelope().len(), limits.max_bytes);
    assert!(answer.response().envelope().contains(&at_limit));
    Ok(())
}

#[test]
fn an_over_budget_release_can_retry_with_a_shorter_request_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let limits = XmlLimits::default();
    let request_id = "_".repeat(limits.max_attribute_value_bytes);
    let message = response_at_envelope_size(limits.max_bytes + 1, &request_id)
        .ok_or("budget cannot hold the envelope")?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    assert!(issued.remove(&artifact));
    issued.store(
        &artifact,
        IssuedArtifact::new(
            parties.sp_metadata.entity_id().clone(),
            message.clone(),
            ArtifactChannelRequirement::Confidential,
            SystemTime::now() + ARTIFACT_LIFETIME,
        ),
    )?;

    let too_large = parties
        .idp
        .answer_artifact_resolve(
            &parties.sp_metadata,
            &resolve_with_id(&artifact, &request_id),
            &EndpointUrl::try_new(RESOLUTION_URL)?,
            &mut issued,
            confidential(),
        )
        .map(|answer| answer.response().envelope().len());
    assert!(
        matches!(too_large, Err(SamlError::LimitExceeded { limit: ResourceLimit::XmlBytes, maximum, .. }) if maximum == limits.max_bytes),
        "expected release to reject an over-budget envelope, got {too_large:?}"
    );
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        resolution.request().endpoint(),
        &mut issued,
        confidential(),
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    assert!(answer.response().envelope().contains(&message));
    assert_eq!(
        resolution
            .finish(answer.response().envelope())?
            .local_name(),
        "Response"
    );
    Ok(())
}
