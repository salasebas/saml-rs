//! Outstanding logout is a caller argument on typed SSO acceptance.
//! Core §3.7.3.1 requires a session participant to apply an accepted
//! LogoutRequest to a later assertion for the same principal and session
//! while that request is still before NotOnOrAfter.
#![cfg(crypto)]

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnSession, BrowserInput, CertificatePem, ClockSkew, Credentials,
    EntityId, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy,
    NameId, NameIdFormat, OutstandingLogout, PendingAuthnRequest, PrivateKeyPem, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, RespondSso, Saml, SamlError, SamlInstant,
    SamlValidationContext, SessionIndex, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, SsoResponse, SsoSession, StartSso, Subject,
};
use time::OffsetDateTime;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[derive(Default)]
struct MemoryReplayCache {
    seen: HashMap<String, SystemTime>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn principal() -> NameId {
    NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress))
}

struct IssuedSso {
    sp: Saml<saml_rs::Sp>,
    idp_descriptor: IdpDescriptor,
    pending: PendingAuthnRequest,
    fields: Vec<FormField>,
    unsolicited_fields: Vec<FormField>,
}

fn issued_sso() -> Result<IssuedSso, Box<dyn std::error::Error>> {
    issued_sso_for(principal())
}

fn issued_sso_for(name_id: NameId) -> Result<IssuedSso, Box<dyn std::error::Error>> {
    let sp_config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
        .credentials(credentials())
        .validation(SpValidationPolicy::recommended())
        .build()?;
    let idp_config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
        .slo_endpoint(SloEndpoint::redirect("https://idp.example.com/slo")?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::recommended())
        .build()?;
    let sp = Saml::sp(sp_config)?;
    let idp = Saml::idp(idp_config)?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let relay_state = RelayStateParam::try_from_option(Some("return".to_string()))?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        open_validation(unix_seconds()?)?,
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(name_id.clone(), Vec::new()),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    )?;
    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        Subject::new(name_id.clone(), Vec::new()),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    )?;
    Ok(IssuedSso {
        sp,
        idp_descriptor,
        pending: started.pending,
        fields: response.post_form()?.fields().to_vec(),
        unsolicited_fields: unsolicited.post_form()?.fields().to_vec(),
    })
}

fn time_invalid(message: &str) -> SamlError {
    SamlError::Invalid(message.into())
}

fn unix_seconds() -> Result<i64, SamlError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| time_invalid("validation instant is before the Unix epoch"))?;
    i64::try_from(elapsed.as_secs()).map_err(|_| time_invalid("validation instant is too large"))
}

fn system_time_at(seconds: i64) -> Result<SystemTime, SamlError> {
    let seconds =
        u64::try_from(seconds).map_err(|_| time_invalid("validation instant is negative"))?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn instant_at(seconds: i64) -> Result<SamlInstant, SamlError> {
    let offset = OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| time_invalid("validation instant cannot be represented as UTC"))?;
    SamlInstant::try_new(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        offset.year(),
        u8::from(offset.month()),
        offset.day(),
        offset.hour(),
        offset.minute(),
        offset.second(),
    ))
}

fn open_validation(seconds: i64) -> Result<SamlValidationContext<'static>, SamlError> {
    validation_at(seconds, ClockSkew::strict())
}

fn validation_at(
    seconds: i64,
    skew: ClockSkew,
) -> Result<SamlValidationContext<'static>, SamlError> {
    Ok(SamlValidationContext::new(
        system_time_at(seconds)?,
        ReplayPolicy::DisabledForCompatibility,
    )
    .with_clock_skew(skew))
}

fn logout(
    principal: NameId,
    sessions: Vec<SessionIndex>,
    not_on_or_after_seconds: i64,
) -> Result<OutstandingLogout, SamlError> {
    OutstandingLogout::try_new(principal, sessions, instant_at(not_on_or_after_seconds)?)
}

fn session_index(session: &SsoSession) -> Result<SessionIndex, Box<dyn std::error::Error>> {
    session
        .authn_sessions()
        .iter()
        .find_map(AuthnSession::session_index)
        .cloned()
        .ok_or_else(|| "expected the assertion to carry a SessionIndex".into())
}

fn finish(
    issued: &IssuedSso,
    seconds: i64,
    skew: ClockSkew,
    outstanding: Option<&OutstandingLogout>,
) -> Result<SsoSession, SamlError> {
    let validation = validation_at(seconds, skew)?;
    let input = BrowserInput::<SsoResponse>::post(issued.fields.clone());
    match outstanding {
        Some(outstanding) => issued.sp.finish_sso_with_outstanding_logout(
            &issued.idp_descriptor,
            &issued.pending,
            input,
            validation,
            outstanding,
        ),
        None => issued
            .sp
            .finish_sso(&issued.idp_descriptor, &issued.pending, input, validation),
    }
}

fn accept_unsolicited(
    issued: &IssuedSso,
    seconds: i64,
    skew: ClockSkew,
    outstanding: Option<&OutstandingLogout>,
) -> Result<SsoSession, SamlError> {
    let validation = validation_at(seconds, skew)?;
    let input = BrowserInput::<SsoResponse>::post(issued.unsolicited_fields.clone());
    match outstanding {
        Some(outstanding) => issued.sp.accept_unsolicited_sso_with_outstanding_logout(
            &issued.idp_descriptor,
            input,
            validation,
            outstanding,
        ),
        None => issued
            .sp
            .accept_unsolicited_sso(&issued.idp_descriptor, input, validation),
    }
}

#[test]
fn finish_sso_rejects_a_later_assertion_for_the_same_principal_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    assert_eq!(accepted.name_id(), &principal());
    let index = session_index(&accepted)?;

    let outstanding = logout(principal(), vec![index], now + 120)?;
    match finish(&issued, now, ClockSkew::strict(), Some(&outstanding)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!(
            "expected the outstanding logout to reject finish_sso, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn accept_unsolicited_sso_rejects_a_later_assertion_for_the_same_principal_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let accepted = accept_unsolicited(&issued, now, ClockSkew::strict(), None)?;
    assert_eq!(accepted.in_response_to(), None);
    let index = session_index(&accepted)?;

    let outstanding = logout(
        principal(),
        vec![index.clone(), SessionIndex::try_new("_other")?],
        now + 120,
    )?;
    match accept_unsolicited(&issued, now, ClockSkew::strict(), Some(&outstanding)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!(
            "expected the outstanding logout to reject accept_unsolicited_sso, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn outstanding_logout_at_or_after_not_on_or_after_does_not_reject(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    let index = session_index(&accepted)?;
    let at_deadline = logout(principal(), vec![index.clone()], now)?;
    let expired = logout(principal(), vec![index], now - 60)?;

    let at_deadline = finish(&issued, now, ClockSkew::strict(), Some(&at_deadline))?;
    assert_eq!(at_deadline.name_id().value(), "alice@example.com");
    let expired = finish(&issued, now, ClockSkew::strict(), Some(&expired))?;
    assert_eq!(expired.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn outstanding_logout_uses_the_not_on_or_after_clock_skew() -> Result<(), Box<dyn std::error::Error>>
{
    let issued = issued_sso()?;
    // The assertion's NotBefore is its issue instant. Validate two minutes
    // later so a one-minute NotBefore skew still leaves that window open.
    let now = unix_seconds()? + 120;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    let index = session_index(&accepted)?;
    let thirty_seconds_ago = logout(principal(), vec![index.clone()], now - 30)?;
    let one_minute_ago = logout(principal(), vec![index.clone()], now - 60)?;
    let at_now = logout(principal(), vec![index], now)?;
    let minute = ClockSkew::from_millis(0, 60_000);

    match finish(&issued, now, minute, Some(&thirty_seconds_ago)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => {}
        other => {
            return Err(format!(
                "expected 60s of NotOnOrAfter skew to keep a 30s-old logout in force, got {other:?}"
            )
            .into());
        }
    }
    let accepted = finish(&issued, now, minute, Some(&one_minute_ago))?;
    assert_eq!(accepted.name_id().value(), "alice@example.com");

    let not_before_only = ClockSkew::from_millis(60_000, 0);
    let accepted = finish(&issued, now, not_before_only, Some(&at_now))?;
    assert_eq!(accepted.name_id().value(), "alice@example.com");

    match finish(&issued, now, minute, Some(&at_now)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!(
            "expected NotOnOrAfter skew to keep a logout at the validation instant in force, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn outstanding_logout_does_not_reject_a_different_principal_or_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    let index = session_index(&accepted)?;
    let other_principal = logout(
        NameId::new("bob@example.com", Some(NameIdFormat::EmailAddress)),
        vec![index.clone()],
        now + 120,
    )?;
    let other_session = logout(
        principal(),
        vec![SessionIndex::try_new("_other-session")?],
        now + 120,
    )?;
    let other_format = logout(
        NameId::new("alice@example.com", Some(NameIdFormat::Persistent)),
        vec![index],
        now + 120,
    )?;

    assert_eq!(
        finish(&issued, now, ClockSkew::strict(), Some(&other_principal))?
            .name_id()
            .value(),
        "alice@example.com"
    );
    assert_eq!(
        finish(&issued, now, ClockSkew::strict(), Some(&other_session))?
            .name_id()
            .value(),
        "alice@example.com"
    );
    assert_eq!(
        finish(&issued, now, ClockSkew::strict(), Some(&other_format))?
            .name_id()
            .value(),
        "alice@example.com"
    );
    Ok(())
}

#[test]
fn outstanding_logout_with_unspecified_format_rejects_an_assertion_without_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso_for(NameId::new("alice@example.com", None))?;
    let now = unix_seconds()? + 2;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    assert_eq!(accepted.name_id().format(), None);

    let outstanding = logout(
        NameId::new("alice@example.com", Some(NameIdFormat::Unspecified)),
        Vec::new(),
        now + 120,
    )?;
    match finish(&issued, now, ClockSkew::strict(), Some(&outstanding)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!(
            "expected an unspecified-format logout to reject an assertion without Format, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn outstanding_logout_with_a_custom_spelling_of_the_format_rejects_the_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let email = NameIdFormat::EmailAddress.as_uri();
    let unspecified = NameIdFormat::Unspecified.as_uri();
    for spelling in [
        email.to_string(),
        format!(" {email} "),
        format!(" {unspecified} "),
    ] {
        let outstanding = logout(
            NameId::new(
                "alice@example.com",
                Some(NameIdFormat::Custom(spelling.clone())),
            ),
            Vec::new(),
            now + 120,
        )?;
        match finish(&issued, now, ClockSkew::strict(), Some(&outstanding)) {
            Err(SamlError::AssertionMatchesOutstandingLogout) => {}
            other => {
                return Err(format!("Format {spelling:?} should reject, got {other:?}").into());
            }
        }
    }
    Ok(())
}

#[test]
fn outstanding_logout_without_a_session_index_rejects_every_session_of_the_principal(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let value_only = logout(
        NameId::new("alice@example.com", None),
        Vec::new(),
        now + 120,
    )?;
    match finish(&issued, now, ClockSkew::strict(), Some(&value_only)) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => Ok(()),
        other => Err(format!(
            "expected a logout with no SessionIndex to reject the principal, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn rejected_outstanding_logout_still_records_the_bearer_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = issued_sso()?;
    let now = unix_seconds()? + 2;
    let accepted = finish(&issued, now, ClockSkew::strict(), None)?;
    let outstanding = logout(principal(), vec![session_index(&accepted)?], now + 120)?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(system_time_at(now)?, ReplayPolicy::RequireCache(&mut cache));
    match issued.sp.finish_sso_with_outstanding_logout(
        &issued.idp_descriptor,
        &issued.pending,
        BrowserInput::<SsoResponse>::post(issued.fields.clone()),
        validation,
        &outstanding,
    ) {
        Err(SamlError::AssertionMatchesOutstandingLogout) => {}
        other => {
            return Err(format!(
                "expected the outstanding logout to reject before reuse, got {other:?}"
            )
            .into());
        }
    }

    match issued.sp.finish_sso(
        &issued.idp_descriptor,
        &issued.pending,
        BrowserInput::<SsoResponse>::post(issued.fields.clone()),
        SamlValidationContext::new(system_time_at(now)?, ReplayPolicy::RequireCache(&mut cache)),
    ) {
        Err(SamlError::ReplayDetected { .. }) => Ok(()),
        other => Err(format!(
            "expected the rejected assertion identifier to stay in the caller cache, got {other:?}"
        )
        .into()),
    }
}
