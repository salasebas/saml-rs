use super::{AssertionId, EndpointUrl, MessageId, SamlInstant};
use crate::error::{SamlError, TimeWindowField};
use std::time::{Duration, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Clock skew applied to SAML time-window checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSkew {
    not_before_ms: i64,
    not_on_or_after_ms: i64,
}

impl ClockSkew {
    /// No clock skew tolerance.
    pub fn strict() -> Self {
        Self {
            not_before_ms: 0,
            not_on_or_after_ms: 0,
        }
    }

    /// Five minutes of skew on `NotBefore` and `NotOnOrAfter`.
    ///
    /// [`SamlValidationContext::new`] starts here. Approved Errata 05 E92
    /// calls three to five minutes reasonable.
    pub fn five_minutes() -> Self {
        const FIVE_MINUTES_MS: i64 = 5 * 60 * 1_000;
        Self::from_millis(-FIVE_MINUTES_MS, FIVE_MINUTES_MS)
    }

    /// Build clock skew from the raw SAML drift values, in milliseconds.
    ///
    /// The first argument applies to `NotBefore`; the second applies to
    /// `NotOnOrAfter`.
    pub fn from_millis(not_before_ms: i64, not_on_or_after_ms: i64) -> Self {
        Self {
            not_before_ms,
            not_on_or_after_ms,
        }
    }

    /// Return a copy with the `NotBefore` skew, in milliseconds.
    pub fn with_not_before_millis(mut self, not_before_ms: i64) -> Self {
        self.not_before_ms = not_before_ms;
        self
    }

    /// Return a copy with the `NotOnOrAfter` skew, in milliseconds.
    pub fn with_not_on_or_after_millis(mut self, not_on_or_after_ms: i64) -> Self {
        self.not_on_or_after_ms = not_on_or_after_ms;
        self
    }

    /// `NotBefore` skew, in milliseconds.
    pub fn not_before_millis(self) -> i64 {
        self.not_before_ms
    }

    /// `NotOnOrAfter` skew, in milliseconds.
    pub fn not_on_or_after_millis(self) -> i64 {
        self.not_on_or_after_ms
    }

    /// Return the raw `(NotBefore, NotOnOrAfter)` drift tuple.
    pub fn as_millis(self) -> (i64, i64) {
        (self.not_before_ms, self.not_on_or_after_ms)
    }
}

impl Default for ClockSkew {
    /// Zero skew. [`SamlValidationContext::new`] does not use this.
    fn default() -> Self {
        Self::strict()
    }
}

/// Replay cache key derived from a validated SAML message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[expect(
    clippy::enum_variant_names,
    reason = "variants name the exact SAML identifier family used in stable cache keys"
)]
pub enum ReplayKey {
    /// SAML AuthnRequest ID.
    AuthnRequestId(MessageId),
    /// SAML LogoutRequest ID.
    LogoutRequestId(MessageId),
    /// SAML LogoutResponse ID.
    LogoutResponseId(MessageId),
    /// SAML protocol response ID.
    ResponseId(MessageId),
    /// SAML assertion ID.
    AssertionId(AssertionId),
}

impl ReplayKey {
    /// Stable key family.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthnRequestId(_) => "authn_request_id",
            Self::LogoutRequestId(_) => "logout_request_id",
            Self::LogoutResponseId(_) => "logout_response_id",
            Self::ResponseId(_) => "response_id",
            Self::AssertionId(_) => "assertion_id",
        }
    }

    /// Raw SAML identifier value.
    pub fn value(&self) -> &str {
        match self {
            Self::AuthnRequestId(id) | Self::LogoutRequestId(id) | Self::LogoutResponseId(id) => {
                id.as_str()
            }
            Self::ResponseId(id) => id.as_str(),
            Self::AssertionId(id) => id.as_str(),
        }
    }

    /// Namespaced key suitable for cache storage and replay error payloads.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.kind(), self.value())
    }
}

/// Caller-owned replay cache.
///
/// Implementations should atomically reject duplicate keys and return
/// [`SamlError::ReplayDetected`] for duplicate SAML messages.
///
/// # Examples
///
/// This is a minimal in-memory example for a single process. Applications
/// should use shared durable storage when multiple processes handle SAML
/// responses.
///
/// ```
/// use std::{collections::HashMap, time::{Duration, SystemTime}};
///
/// use saml_rs::{
///     ReplayCache, ReplayKey, ReplayPolicy, SamlError, SamlValidationContext,
/// };
///
/// #[derive(Default)]
/// struct MinimalReplayCache {
///     seen: HashMap<String, SystemTime>,
/// }
///
/// impl ReplayCache for MinimalReplayCache {
///     fn check_and_store(
///         &mut self,
///         key: ReplayKey,
///         expires_at: SystemTime,
///     ) -> Result<(), SamlError> {
///         let cache_key = key.cache_key();
///         if self.seen.contains_key(&cache_key) {
///             return Err(SamlError::ReplayDetected { key: cache_key });
///         }
///         self.seen.insert(cache_key, expires_at);
///         Ok(())
///     }
/// }
///
/// let now = SystemTime::now();
/// let mut cache = MinimalReplayCache::default();
/// let validation = SamlValidationContext::new(
///     now,
///     ReplayPolicy::RequireCache(&mut cache),
/// )
/// .with_replay_retention(Duration::from_secs(5 * 60));
/// # let _ = validation;
/// ```
pub trait ReplayCache {
    /// Check whether `key` has already been seen, then store it until
    /// `expires_at` if it is new.
    ///
    /// # Errors
    ///
    /// Implementations should return [`SamlError::ReplayDetected`] for
    /// duplicate keys. They may also return storage-specific failures mapped
    /// to [`SamlError`] if cache access fails.
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError>;
}

/// Replay behavior for typed inbound browser flows.
///
/// This is a caller argument on [`SamlValidationContext::new`], not a field of
/// [`crate::SpValidationPolicy`] or [`crate::IdpValidationPolicy`]. There is
/// no `recommended()` constructor. The classification is
/// `docs/conformance/metadata-and-replay.md`.
#[non_exhaustive]
pub enum ReplayPolicy<'a> {
    /// Skip replay checks. The raw API and the samlify port have no replay cache.
    DisabledForCompatibility,
    /// Require the caller to provide replay storage.
    RequireCache(&'a mut dyn ReplayCache),
}

/// Maximum age for an inbound `AuthnRequest` `IssueInstant`.
///
/// [`Self::Disabled`] skips the comparison. [`Self::Bounded`] accepts an
/// instant inside an inclusive window of `max_age`, widened by the context
/// clock skew. The classification is
/// `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnRequestAgePolicy {
    /// Do not compare `IssueInstant` with the validation clock.
    Disabled,
    /// Accept an `IssueInstant` inside an inclusive window of `max_age`.
    Bounded {
        /// Maximum age before clock-skew tolerance is applied.
        ///
        /// Zero leaves only the skew neighborhood.
        max_age: Duration,
    },
}

/// Caller-owned validation context for typed inbound SAML messages.
pub struct SamlValidationContext<'a> {
    now: SystemTime,
    recipient_endpoint: Option<EndpointUrl>,
    clock_skew: ClockSkew,
    authn_request_age: AuthnRequestAgePolicy,
    replay: ReplayPolicy<'a>,
    replay_retention: Option<Duration>,
}

impl<'a> SamlValidationContext<'a> {
    /// Build a validation context that allows five minutes of clock skew.
    ///
    /// The same skew covers assertion conditions, bearer confirmation,
    /// `SessionNotOnOrAfter`, and `LogoutRequest@NotOnOrAfter`.
    /// [`Self::with_clock_skew`] replaces it.
    pub fn new(now: SystemTime, replay: ReplayPolicy<'a>) -> Self {
        Self {
            now,
            recipient_endpoint: None,
            clock_skew: ClockSkew::five_minutes(),
            authn_request_age: AuthnRequestAgePolicy::Disabled,
            replay,
            replay_retention: None,
        }
    }

    /// Replace the context clock skew, including [`ClockSkew::strict`].
    pub fn with_clock_skew(mut self, clock_skew: ClockSkew) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Set the actual receiving URL for `receive_sso`, `receive_slo`, or `finish_slo`.
    ///
    /// Supply the URL from the HTTP handler, never from the message's
    /// `Destination`. It must be published for the incoming binding and
    /// message direction. When omitted, these methods infer a unique
    /// published URL and reject ambiguous metadata.
    pub fn with_recipient_endpoint(mut self, endpoint: EndpointUrl) -> Self {
        self.recipient_endpoint = Some(endpoint);
        self
    }

    /// Actual receiving URL supplied for browser SSO requests or logout messages.
    pub fn recipient_endpoint(&self) -> Option<&EndpointUrl> {
        self.recipient_endpoint.as_ref()
    }

    pub(crate) fn resolve_recipient_endpoint(
        &self,
        published: &[String],
    ) -> Result<String, SamlError> {
        if let Some(endpoint) = &self.recipient_endpoint {
            if published
                .iter()
                .any(|location| location == endpoint.as_str())
            {
                return Ok(endpoint.as_str().to_string());
            }
            return Err(SamlError::Invalid(
                "receiving endpoint is not published for this binding and message direction".into(),
            ));
        }
        match published {
            [endpoint] => Ok(endpoint.clone()),
            _ => Err(SamlError::Invalid(
                "multiple receiving endpoints require with_recipient_endpoint".into(),
            )),
        }
    }

    /// Select the maximum age of an inbound `AuthnRequest` `IssueInstant`.
    ///
    /// [`AuthnRequestAgePolicy::Disabled`] skips the comparison.
    /// [`AuthnRequestAgePolicy::Bounded`] accepts an instant at or after
    /// `now - max_age - past_tolerance` and at or before
    /// `now + future_tolerance`. Both edges are inclusive. Past tolerance is
    /// the positive `NotOnOrAfter` skew. Future tolerance is the magnitude of
    /// a negative `NotBefore` skew. Zero skew and inverted skew do not shrink
    /// `max_age`.
    pub fn with_authn_request_age(mut self, authn_request_age: AuthnRequestAgePolicy) -> Self {
        self.authn_request_age = authn_request_age;
        self
    }

    /// Set explicit replay retention for protocol messages that do not carry a
    /// SAML `NotOnOrAfter` value suitable for cache expiry.
    pub fn with_replay_retention(mut self, retention: Duration) -> Self {
        self.replay_retention = Some(retention);
        self
    }

    /// Validation instant supplied by the caller.
    pub fn now(&self) -> SystemTime {
        self.now
    }

    /// Clock skew applied to time-window checks.
    pub fn clock_skew(&self) -> ClockSkew {
        self.clock_skew
    }

    /// Maximum age policy for an inbound `AuthnRequest` `IssueInstant`.
    pub fn authn_request_age(&self) -> AuthnRequestAgePolicy {
        self.authn_request_age
    }

    /// Replay retention for protocol message IDs without SAML expiry.
    pub fn replay_retention(&self) -> Option<Duration> {
        self.replay_retention
    }

    pub(crate) fn now_offset(&self) -> Result<OffsetDateTime, SamlError> {
        crate::validator::offset_datetime_from_system_time(self.now)
    }

    pub(crate) fn replay_policy(&mut self) -> &mut ReplayPolicy<'a> {
        &mut self.replay
    }

    pub(crate) fn check_authn_request_issue_instant(
        &self,
        issue_instant: &SamlInstant,
    ) -> Result<(), SamlError> {
        let AuthnRequestAgePolicy::Bounded { max_age } = self.authn_request_age else {
            return Ok(());
        };
        let past_tolerance = positive_millis(self.clock_skew.not_on_or_after_millis());
        let future_tolerance = negative_millis_magnitude(self.clock_skew.not_before_millis());
        let past_allowance = max_age
            .checked_add(past_tolerance)
            .ok_or_else(authn_request_issue_instant_window)?;
        let now = self
            .now_offset()
            .map_err(|_| authn_request_issue_instant_window())?;
        let earliest = offset_checked_sub(now, past_allowance)?;
        let latest = offset_checked_add(now, future_tolerance)?;
        let issued = OffsetDateTime::parse(issue_instant.as_str(), &Rfc3339)
            .map_err(|_| authn_request_issue_instant_window())?;
        if issued < earliest || issued > latest {
            return Err(authn_request_issue_instant_window());
        }
        Ok(())
    }

    pub(crate) fn check_and_store_message_replay(
        &mut self,
        key: ReplayKey,
    ) -> Result<(), SamlError> {
        if matches!(&self.replay, ReplayPolicy::DisabledForCompatibility) {
            return Ok(());
        }
        let expires_at = self.message_replay_expires_at()?;
        match &mut self.replay {
            ReplayPolicy::DisabledForCompatibility => Ok(()),
            ReplayPolicy::RequireCache(cache) => cache.check_and_store(key, expires_at),
        }
    }

    pub(crate) fn check_and_store_message_replay_until(
        &mut self,
        key: ReplayKey,
        derived_deadline: Option<OffsetDateTime>,
    ) -> Result<(), SamlError> {
        if matches!(&self.replay, ReplayPolicy::DisabledForCompatibility) {
            return Ok(());
        }
        let expires_at = derived_deadline
            .map(system_time_from_offset_datetime)
            .transpose()?
            .map_or_else(|| self.message_replay_expires_at(), Ok)?;
        match &mut self.replay {
            ReplayPolicy::DisabledForCompatibility => Ok(()),
            ReplayPolicy::RequireCache(cache) => cache.check_and_store(key, expires_at),
        }
    }

    fn message_replay_expires_at(&self) -> Result<SystemTime, SamlError> {
        let Some(retention) = self.replay_retention else {
            return Err(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            });
        };
        if retention <= Duration::ZERO {
            return Err(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            });
        }
        self.now
            .checked_add(retention)
            .ok_or(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            })
    }
}

fn positive_millis(millis: i64) -> Duration {
    u64::try_from(millis)
        .ok()
        .filter(|millis| *millis > 0)
        .map_or(Duration::ZERO, Duration::from_millis)
}

fn negative_millis_magnitude(millis: i64) -> Duration {
    if millis < 0 {
        Duration::from_millis(millis.unsigned_abs())
    } else {
        Duration::ZERO
    }
}

fn authn_request_issue_instant_window() -> SamlError {
    SamlError::TimeWindowInvalid {
        field: TimeWindowField::AuthnRequestIssueInstant,
    }
}

fn offset_checked_add(
    instant: OffsetDateTime,
    duration: Duration,
) -> Result<OffsetDateTime, SamlError> {
    let duration =
        time::Duration::try_from(duration).map_err(|_| authn_request_issue_instant_window())?;
    instant
        .checked_add(duration)
        .ok_or_else(authn_request_issue_instant_window)
}

fn offset_checked_sub(
    instant: OffsetDateTime,
    duration: Duration,
) -> Result<OffsetDateTime, SamlError> {
    let duration =
        time::Duration::try_from(duration).map_err(|_| authn_request_issue_instant_window())?;
    instant
        .checked_sub(duration)
        .ok_or_else(authn_request_issue_instant_window)
}

fn system_time_from_offset_datetime(deadline: OffsetDateTime) -> Result<SystemTime, SamlError> {
    let since_epoch = deadline - OffsetDateTime::UNIX_EPOCH;
    let converted = if since_epoch.is_negative() {
        SystemTime::UNIX_EPOCH.checked_sub(since_epoch.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH.checked_add(since_epoch.unsigned_abs())
    };
    converted.ok_or(SamlError::TimeWindowInvalid {
        field: TimeWindowField::ReplayExpiration,
    })
}
