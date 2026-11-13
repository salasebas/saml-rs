#![cfg(crypto)]

#[path = "common/replay_cache.rs"]
mod replay_cache;

use replay_cache::RecordingReplayCache;
use std::time::{Duration, SystemTime};

use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode, deflate_raw_encode};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{
    AcsEndpoint, BrowserInput, EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    LogoutPolicy, LogoutRequest, MetadataTrustPolicy, ReplayCache, ReplayPolicy, Saml, SamlError,
    SamlValidationContext, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const SP_ENTITY_ID: &str = "https://sp.example.test/metadata";
const SP_ACS_POST: &str = "https://sp.example.test/acs/post";
const SP_SLO_REDIRECT: &str = "https://localhost:24720/sp/SAML2/Redirect/SLO";
const SHIBBOLETH_IDP_ENTITY_ID: &str = "https://idp.example.org";
const SHIBBOLETH_REQUEST_ID: &str = "_bf782bbc9316aebfd833c4ba368a9ee2";
const SHIBBOLETH_ISSUE_INSTANT: &str = "2026-07-24T07:38:43.086Z";
const SHIBBOLETH_SESSION_INDEX: &str = "_6bf9971c68fae97ec8a850ee6e99b3ca";
const IDP_ENTITY_ID: &str = "https://idp.example.test/metadata";
const IDP_SSO_REDIRECT: &str = "https://idp.example.test/sso/redirect";
const IDP_SLO_REDIRECT: &str = "https://idp.example.test/slo/redirect";
const SIMPLESAMLPHP_SP_ENTITY_ID: &str = "https://sp.example.test/saml2";
const SIMPLESAMLPHP_REQUEST_ID: &str = "_simplesamlphp-sp-redirect-logout-request";
const SIMPLESAMLPHP_ISSUE_INSTANT: &str = "2026-07-24T06:05:00Z";
const SIMPLESAMLPHP_NAME_ID: &str = "bob@example.test";
const SIMPLESAMLPHP_SESSION_INDEXES: [&str; 2] = [
    "_simplesamlphp-session-20260724",
    "_simplesamlphp-session-secondary",
];
const MISMATCHED_DESTINATION: &str = "https://untrusted.example.test/slo/redirect";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

const SHIBBOLETH_QUERY: &str =
    include_str!("fixtures/interop/shibboleth-idp-5.2.3/logout-request.query");
const SHIBBOLETH_METADATA: &str =
    include_str!("fixtures/interop/shibboleth-idp-5.2.3/idp-metadata.xml");
const SIMPLESAMLPHP_QUERY: &str =
    include_str!("fixtures/interop/simplesamlphp-2.5.2/logout-request.query");
const SIMPLESAMLPHP_METADATA: &str =
    include_str!("fixtures/interop/simplesamlphp-2.5.2/sp-metadata.xml");

fn fixed_time(value: &str) -> Result<SystemTime, Box<dyn std::error::Error>> {
    Ok(SystemTime::from(OffsetDateTime::parse(value, &Rfc3339)?))
}

fn fixture_query(contents: &str) -> &str {
    contents.strip_suffix('\n').unwrap_or(contents)
}

fn assert_redirect_wire(query: &str, relay_state: Option<&str>) {
    let names = query
        .split('&')
        .filter_map(|segment| segment.split_once('=').map(|(name, _)| name))
        .collect::<Vec<_>>();
    match relay_state {
        Some(value) => {
            assert_eq!(names, ["SAMLRequest", "RelayState", "SigAlg", "Signature"]);
            assert!(query.contains(&format!("&RelayState={value}&")));
        }
        None => assert_eq!(names, ["SAMLRequest", "SigAlg", "Signature"]),
    }
    assert!(query.contains(
        "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature="
    ));
}

fn sp_receiver() -> Result<Saml<saml_rs::Sp>, SamlError> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.logout = LogoutPolicy::recommended();
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
            .slo_endpoint(SloEndpoint::redirect(SP_SLO_REDIRECT)?)
            .validation(validation)
            .build()?,
    )
}

fn shibboleth_idp_descriptor() -> Result<IdpDescriptor, SamlError> {
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SHIBBOLETH_IDP_ENTITY_ID)?,
        SHIBBOLETH_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn idp_receiver() -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut validation = IdpValidationPolicy::compatibility();
    validation.logout = LogoutPolicy::recommended();
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
            .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
            .validation(validation)
            .build()?,
    )
}

fn simplesamlphp_sp_descriptor() -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SIMPLESAMLPHP_SP_ENTITY_ID)?,
        SIMPLESAMLPHP_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn validation_at<'a>(
    issue_instant: &str,
    cache: &'a mut dyn ReplayCache,
) -> Result<SamlValidationContext<'a>, Box<dyn std::error::Error>> {
    Ok(SamlValidationContext::new(
        fixed_time(issue_instant)?,
        ReplayPolicy::RequireCache(cache),
    )
    .with_replay_retention(Duration::from_secs(5 * 60)))
}

fn tamper_redirect_message(
    raw_query: &str,
    original: &str,
    replacement: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut changed = false;
    let mut segments = Vec::new();
    for segment in raw_query.trim().split('&') {
        let Some((name, _)) = segment.split_once('=') else {
            segments.push(segment.to_string());
            continue;
        };
        if name != "SAMLRequest" {
            segments.push(segment.to_string());
            continue;
        }

        let decoded = url::form_urlencoded::parse(segment.as_bytes())
            .next()
            .ok_or("missing SAMLRequest value")?
            .1;
        let xml = String::from_utf8(deflate_raw_decode(&base64_decode(decoded.as_ref())?)?)?;
        let tampered = xml.replacen(original, replacement, 1);
        if tampered == xml {
            return Err(format!("signed value {original:?} was not present").into());
        }
        let encoded = base64_encode(&deflate_raw_encode(tampered.as_bytes())?);
        let encoded: String = url::form_urlencoded::byte_serialize(encoded.as_bytes()).collect();
        segments.push(format!("{name}={encoded}"));
        changed = true;
    }
    if !changed {
        return Err("missing SAMLRequest query parameter".into());
    }
    Ok(segments.join("&"))
}

fn redirect_message_xml(raw_query: &str) -> Result<String, Box<dyn std::error::Error>> {
    let saml_request = raw_query
        .trim()
        .split('&')
        .find(|segment| segment.starts_with("SAMLRequest="))
        .ok_or("missing SAMLRequest query parameter")?;
    let decoded = url::form_urlencoded::parse(saml_request.as_bytes())
        .next()
        .ok_or("missing SAMLRequest value")?
        .1;
    Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
        decoded.as_ref(),
    )?)?)?)
}

#[test]
fn shibboleth_idp5_redirect_logout_request_is_authenticated_and_parsed_by_sp(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_receiver()?;
    let idp = shibboleth_idp_descriptor()?;
    let mut cache = RecordingReplayCache::default();

    let received = sp.receive_slo(
        &idp,
        BrowserInput::<LogoutRequest>::redirect(fixture_query(SHIBBOLETH_QUERY)),
        validation_at(SHIBBOLETH_ISSUE_INSTANT, &mut cache)?,
    )?;
    let message = received.message();

    assert_eq!(message.issuer().as_str(), SHIBBOLETH_IDP_ENTITY_ID);
    assert_eq!(
        message.destination().map(|value| value.as_str()),
        Some(SP_SLO_REDIRECT)
    );
    assert_eq!(message.id().as_str(), SHIBBOLETH_REQUEST_ID);
    assert_eq!(message.issue_instant().as_str(), SHIBBOLETH_ISSUE_INSTANT);
    assert!(message.name_id().is_none());
    let wire_xml = redirect_message_xml(fixture_query(SHIBBOLETH_QUERY))?;
    let subject = extract(
        &wire_xml,
        &[
            ExtractorField::new("encryptedID", &["LogoutRequest", "EncryptedID"]).with_context(),
            ExtractorField::new("nameID", &["LogoutRequest", "NameID"]).with_context(),
        ],
    )?;
    assert!(subject.get_str("encryptedID").is_some());
    assert!(subject.get_str("nameID").is_none());
    assert_eq!(
        message
            .session_indexes()
            .iter()
            .map(|index| index.as_str())
            .collect::<Vec<_>>(),
        [SHIBBOLETH_SESSION_INDEX]
    );
    assert_eq!(message.raw_flow().sig_alg.as_deref(), Some(RSA_SHA256));
    assert_eq!(received.relay_state().as_deref(), None);
    assert_redirect_wire(fixture_query(SHIBBOLETH_QUERY), None);
    assert_eq!(
        cache.seen.keys().next().map(String::as_str),
        Some("logout_request_id:_bf782bbc9316aebfd833c4ba368a9ee2")
    );
    assert_eq!(cache.seen.len(), 1);

    let tampered_query = tamper_redirect_message(
        fixture_query(SHIBBOLETH_QUERY),
        SP_SLO_REDIRECT,
        MISMATCHED_DESTINATION,
    )?;
    let mut tampered_cache = RecordingReplayCache::default();
    let result = sp.receive_slo(
        &idp,
        BrowserInput::<LogoutRequest>::redirect(tampered_query),
        validation_at(SHIBBOLETH_ISSUE_INSTANT, &mut tampered_cache)?,
    );
    assert!(matches!(
        result,
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::DetachedMessageSignature,
        })
    ));
    assert!(tampered_cache.seen.is_empty());

    Ok(())
}

#[test]
fn simplesamlphp_sp_redirect_logout_request_is_consumed_by_idp(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_receiver()?;
    let sp = simplesamlphp_sp_descriptor()?;
    let mut cache = RecordingReplayCache::default();

    let received = idp.receive_slo(
        &sp,
        BrowserInput::<LogoutRequest>::redirect(fixture_query(SIMPLESAMLPHP_QUERY)),
        validation_at(SIMPLESAMLPHP_ISSUE_INSTANT, &mut cache)?,
    )?;
    let message = received.message();

    assert_eq!(message.issuer().as_str(), SIMPLESAMLPHP_SP_ENTITY_ID);
    assert_eq!(
        message.destination().map(|value| value.as_str()),
        Some(IDP_SLO_REDIRECT)
    );
    assert_eq!(message.id().as_str(), SIMPLESAMLPHP_REQUEST_ID);
    assert_eq!(
        message.issue_instant().as_str(),
        SIMPLESAMLPHP_ISSUE_INSTANT
    );
    assert_eq!(
        message.name_id().map(|name_id| name_id.value()),
        Some(SIMPLESAMLPHP_NAME_ID)
    );
    assert_eq!(
        message
            .session_indexes()
            .iter()
            .map(|index| index.as_str())
            .collect::<Vec<_>>(),
        SIMPLESAMLPHP_SESSION_INDEXES
    );
    assert_eq!(message.raw_flow().sig_alg.as_deref(), Some(RSA_SHA256));
    assert_eq!(
        received.relay_state().as_deref(),
        Some("simplesamlphp-sp-state")
    );
    assert_redirect_wire(
        fixture_query(SIMPLESAMLPHP_QUERY),
        Some("simplesamlphp-sp-state"),
    );
    assert_eq!(
        cache.seen.keys().next().map(String::as_str),
        Some("logout_request_id:_simplesamlphp-sp-redirect-logout-request")
    );
    assert_eq!(cache.seen.len(), 1);

    let tampered_query = tamper_redirect_message(
        fixture_query(SIMPLESAMLPHP_QUERY),
        IDP_SLO_REDIRECT,
        MISMATCHED_DESTINATION,
    )?;
    let mut tampered_cache = RecordingReplayCache::default();
    let result = idp.receive_slo(
        &sp,
        BrowserInput::<LogoutRequest>::redirect(tampered_query),
        validation_at(SIMPLESAMLPHP_ISSUE_INSTANT, &mut tampered_cache)?,
    );
    assert!(matches!(
        result,
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::DetachedMessageSignature,
        })
    ));
    assert!(tampered_cache.seen.is_empty());

    Ok(())
}
