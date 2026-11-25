use super::{AssertionId, EndpointUrl, MessageId, SamlInstant};
use crate::artifact::Artifact;
use crate::error::{SamlError, TimeWindowField};
use std::{
    fmt,
    time::{Duration, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Clock skew applied to SAML time-window checks.
///
/// Skew moves each bound of a window on its own. It never opens an assertion
/// `Conditions` or a bearer `SubjectConfirmationData` whose `NotBefore` is
/// not earlier than its `NotOnOrAfter`.
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
    /// `NotOnOrAfter`. A negative `NotBefore` value permits early acceptance;
    /// a positive `NotOnOrAfter` value permits late acceptance.
    pub fn from_millis(not_before_ms: i64, not_on_or_after_ms: i64) -> Self {
        Self {
            not_before_ms,
            not_on_or_after_ms,
        }
    }

    /// `NotBefore` skew, in milliseconds.
    pub fn not_before_millis(self) -> i64 {
        self.not_before_ms
    }

    /// `NotOnOrAfter` skew, in milliseconds.
    pub fn not_on_or_after_millis(self) -> i64 {
        self.not_on_or_after_ms
    }
}

/// Key of a single-use SAML value: a message ID, an assertion ID, or an
/// artifact.
///
/// [`ReplayCache`] receives each of them.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReplayKey {
    /// SAML AuthnRequest ID.
    AuthnRequest(MessageId),
    /// SAML LogoutRequest ID.
    LogoutRequest(MessageId),
    /// SAML LogoutResponse ID.
    LogoutResponse(MessageId),
    /// SAML ManageNameIDRequest ID.
    ManageNameIdRequest(MessageId),
    /// SAML ManageNameIDResponse ID.
    ManageNameIdResponse(MessageId),
    /// SAML Response ID from a Web Browser SSO login.
    SsoResponse(MessageId),
    /// SAML assertion ID.
    Assertion(AssertionId),
    /// SAML artifact resolved by a service provider.
    Artifact(Artifact),
}

impl ReplayKey {
    /// Stable key family.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthnRequest(_) => "authn_request_id",
            Self::LogoutRequest(_) => "logout_request_id",
            Self::LogoutResponse(_) => "logout_response_id",
            Self::ManageNameIdRequest(_) => "manage_name_id_request_id",
            Self::ManageNameIdResponse(_) => "manage_name_id_response_id",
            Self::SsoResponse(_) => "response_id",
            Self::Assertion(_) => "assertion_id",
            Self::Artifact(_) => "artifact",
        }
    }

    /// Raw SAML identifier or artifact value.
    pub fn value(&self) -> &str {
        match self {
            Self::AuthnRequest(id)
            | Self::LogoutRequest(id)
            | Self::LogoutResponse(id)
            | Self::ManageNameIdRequest(id)
            | Self::ManageNameIdResponse(id)
            | Self::SsoResponse(id) => id.as_str(),
            Self::Assertion(id) => id.as_str(),
            Self::Artifact(artifact) => artifact.as_str(),
        }
    }

    /// Namespaced key suitable for cache storage and replay error payloads.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.kind(), self.value())
    }
}

/// Caller-owned replay cache.
///
/// Implementations must atomically reject duplicate keys and return
/// [`SamlError::ReplayDetected`] for duplicate SAML messages.
///
/// Use [`super::InMemoryReplayCache`] for a single process. Multiple processes
/// or protection across restarts require shared durable storage.
///
/// # Examples
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use saml_rs::{InMemoryReplayCache, ReplayPolicy, SamlValidationContext};
///
/// let mut cache = InMemoryReplayCache::new().with_max_entries(10_000);
/// let validation = SamlValidationContext::new(
///     SystemTime::now(), ReplayPolicy::RequireCache(&mut cache),
/// )
/// .with_replay_retention(Duration::from_secs(5 * 60));
/// # let _ = validation;
/// ```
pub trait ReplayCache {
    /// Check whether `key` has already been seen, then store it until
    /// `expires_at` if it is new. For an assertion, return an error if the
    /// deadline has passed before the key can be stored.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::ReplayDetected`] for a duplicate key. If your
    /// store cannot check or retain a key, return [`SamlError::ReplayCacheUnavailable`]
    /// with the cause. Use this error when a new assertion key reaches its
    /// deadline before your store can record it. An assertion key whose
    /// deadline is at or before the validation instant does not reach your
    /// cache: the library returns [`SamlError::TimeWindowInvalid`] instead.
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError>;
}

/// Replay behavior for typed inbound flows.
///
/// With [`Self::RequireCache`], a receive operation stores the `ID` of an
/// authenticated request after every check that refuses it before storage, and
/// the `ID` of a `Success` response. An accepted SSO response also stores its
/// assertion IDs. A message refused or failed before storage is not stored, so
/// a repeat is validated again from the start. A `LogoutRequest` or
/// `ManageNameIDRequest` is stored before its identifier is decrypted, and an
/// SSO response that matches an [`crate::OutstandingLogout`] is stored before
/// it is refused. An artifact is stored when its resolution starts, whatever
/// the outcome. A repeat that reaches the cache while its stored key is
/// retained returns [`SamlError::ReplayDetected`].
///
/// `Debug` identifies the selected policy without exposing cache contents.
///
/// This is a caller argument on [`SamlValidationContext::new`], not a field of
/// [`crate::SpValidationPolicy`] or [`crate::IdpValidationPolicy`]. The classification is
/// `docs/conformance/metadata-and-replay.md`.
#[non_exhaustive]
pub enum ReplayPolicy<'a> {
    /// Supply no replay cache and skip only the storage of message,
    /// assertion, and artifact keys. Signature, issuer, correlation,
    /// destination, and time checks still run.
    /// HTTP-POST SSO acceptance returns [`SamlError::ReplayCacheRequired`].
    NoCache,
    /// Store keys in the caller's replay storage and reject a repeated key.
    RequireCache(&'a mut dyn ReplayCache),
}

impl fmt::Debug for ReplayPolicy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCache => f.write_str("NoCache"),
            Self::RequireCache(_) => f.debug_tuple("RequireCache").finish_non_exhaustive(),
        }
    }
}

/// Maximum age for an inbound authentication or name identifier management request.
///
/// [`Self::Disabled`] skips the comparison. [`Self::Bounded`] accepts an
/// instant inside an inclusive window of `max_age`, widened by the context
/// clock skew. The classification is
/// `docs/conformance/web-browser-sso-acceptance.md` and
/// `docs/conformance/name-id-management.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestAgePolicy {
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

/// Where a request `IssueInstant` falls relative to the configured age window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestAge {
    WithinWindow,
    OutsideWindow,
}

/// Caller-owned validation context for typed inbound SAML messages.
#[derive(Debug)]
pub struct SamlValidationContext<'a> {
    now: SystemTime,
    recipient_endpoint: Option<EndpointUrl>,
    clock_skew: ClockSkew,
    authn_request_age: RequestAgePolicy,
    manage_name_id_request_age: RequestAgePolicy,
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
            authn_request_age: RequestAgePolicy::Disabled,
            manage_name_id_request_age: RequestAgePolicy::Disabled,
            replay,
            replay_retention: None,
        }
    }

    /// Replace the context clock skew, including [`ClockSkew::strict`].
    pub fn with_clock_skew(mut self, clock_skew: ClockSkew) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Set the actual receiving URL for `receive_sso`, `finish_sso`,
    /// `accept_unsolicited_sso`, `receive_slo`, or `finish_slo`.
    ///
    /// Supply the URL from the HTTP handler, never from the message's
    /// `Destination`. It must be published for the incoming binding and
    /// message direction. For a SOAP `finish_slo`, it selects the local SOAP
    /// `SingleLogoutService` that a present `Destination` must name. When
    /// omitted, `finish_sso` expects the assertion consumer of the pending
    /// request, `accept_unsolicited_sso` expects the default assertion
    /// consumer for the incoming binding, and the other methods infer a
    /// unique published URL and reject ambiguous metadata.
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
            return Err(SamlError::RecipientEndpointNotPublished);
        }
        match published {
            [endpoint] => Ok(endpoint.clone()),
            _ => Err(SamlError::RecipientEndpointAmbiguous),
        }
    }

    /// Select the maximum age of an inbound `AuthnRequest` `IssueInstant`.
    ///
    /// [`RequestAgePolicy::Disabled`] skips the comparison.
    /// [`RequestAgePolicy::Bounded`] accepts an instant at or after
    /// `now - max_age - past_tolerance` and at or before
    /// `now + future_tolerance`. Both edges are inclusive. Past tolerance is
    /// the positive `NotOnOrAfter` skew. Future tolerance is the magnitude of
    /// a negative `NotBefore` skew. Zero skew and inverted skew do not shrink
    /// `max_age`.
    pub fn with_authn_request_age(mut self, authn_request_age: RequestAgePolicy) -> Self {
        self.authn_request_age = authn_request_age;
        self
    }

    /// Select the maximum age of a `ManageNameIDRequest` `IssueInstant`
    /// received by `receive_name_id_management` or
    /// `receive_name_id_management_redirect`.
    ///
    /// [`RequestAgePolicy::Bounded`] accepts the window described
    /// on [`Self::with_authn_request_age`]. An authenticated request outside
    /// the window returns [`crate::NameIdManagementReceipt::Refused`]
    /// before its `ID` is stored for replay detection.
    pub fn with_manage_name_id_request_age(
        mut self,
        manage_name_id_request_age: RequestAgePolicy,
    ) -> Self {
        self.manage_name_id_request_age = manage_name_id_request_age;
        self
    }

    /// Set explicit replay retention for protocol messages that do not carry a
    /// SAML `NotOnOrAfter` value suitable for cache expiry.
    ///
    /// These messages are an `AuthnRequest`, a `LogoutRequest` without
    /// `NotOnOrAfter`, a `LogoutResponse`, a `ManageNameIDRequest`, a
    /// `ManageNameIDResponse`, and an artifact. The library has no acceptance
    /// deadline for them, so keep each key for as long as you would
    /// accept the message. With [`Self::with_authn_request_age`], choose a
    /// retention longer than the maximum age plus the clock skew in both
    /// directions, because the window includes both ends and an entry expires
    /// at its deadline.
    ///
    /// Set a positive duration that can be added to the validation instant
    /// ([`Self::now`]). When a receive operation uses this duration for the
    /// replay cache, a missing or zero retention or an unrepresentable deadline
    /// returns [`SamlError::TimeWindowInvalid`] with
    /// [`crate::TimeWindowField::ReplayExpiration`].
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
    pub fn authn_request_age(&self) -> RequestAgePolicy {
        self.authn_request_age
    }

    /// Maximum age policy for a received `ManageNameIDRequest`
    /// `IssueInstant`.
    pub fn manage_name_id_request_age(&self) -> RequestAgePolicy {
        self.manage_name_id_request_age
    }

    pub(crate) fn now_offset(&self) -> Result<OffsetDateTime, SamlError> {
        crate::validator::offset_datetime_from_system_time(self.now)
    }

    pub(crate) fn check_sso_replay_policy(
        &self,
        binding: crate::SsoResponseBinding,
    ) -> Result<(), SamlError> {
        if binding == crate::SsoResponseBinding::Post
            && matches!(self.replay, ReplayPolicy::NoCache)
        {
            return Err(SamlError::ReplayCacheRequired);
        }
        Ok(())
    }

    pub(crate) fn replay_policy(&mut self) -> &mut ReplayPolicy<'a> {
        &mut self.replay
    }

    pub(crate) fn authn_request_issue_instant_age(
        &self,
        issue_instant: &SamlInstant,
    ) -> Result<RequestAge, SamlError> {
        self.issue_instant_age(
            issue_instant,
            self.authn_request_age,
            TimeWindowField::AuthnRequestIssueInstant,
        )
    }

    pub(crate) fn check_manage_name_id_request_issue_instant(
        &self,
        issue_instant: &SamlInstant,
    ) -> Result<(), SamlError> {
        let field = TimeWindowField::ManageNameIdRequestIssueInstant;
        match self.issue_instant_age(issue_instant, self.manage_name_id_request_age, field)? {
            RequestAge::WithinWindow => Ok(()),
            RequestAge::OutsideWindow => Err(SamlError::TimeWindowInvalid { field }),
        }
    }

    fn issue_instant_age(
        &self,
        issue_instant: &SamlInstant,
        policy: RequestAgePolicy,
        field: TimeWindowField,
    ) -> Result<RequestAge, SamlError> {
        let max_age = match policy {
            RequestAgePolicy::Disabled => return Ok(RequestAge::WithinWindow),
            RequestAgePolicy::Bounded { max_age } => max_age,
        };
        let outside_window = || SamlError::TimeWindowInvalid { field };
        let past_tolerance = positive_millis(self.clock_skew.not_on_or_after_millis());
        let future_tolerance = negative_millis_magnitude(self.clock_skew.not_before_millis());
        let past_allowance = max_age
            .checked_add(past_tolerance)
            .ok_or_else(outside_window)?;
        let now = self.now_offset().map_err(|_| outside_window())?;
        let earliest = time::Duration::try_from(past_allowance)
            .ok()
            .and_then(|allowance| now.checked_sub(allowance))
            .ok_or_else(outside_window)?;
        let latest = time::Duration::try_from(future_tolerance)
            .ok()
            .and_then(|tolerance| now.checked_add(tolerance))
            .ok_or_else(outside_window)?;
        let issued = OffsetDateTime::parse(issue_instant.as_str(), &Rfc3339)
            .map_err(|_| outside_window())?;
        if issued < earliest || issued > latest {
            return Ok(RequestAge::OutsideWindow);
        }
        Ok(RequestAge::WithinWindow)
    }

    pub(crate) fn check_and_store_message_replay(
        &mut self,
        key: ReplayKey,
    ) -> Result<(), SamlError> {
        if matches!(&self.replay, ReplayPolicy::NoCache) {
            return Ok(());
        }
        let expires_at = self.message_replay_expires_at()?;
        match &mut self.replay {
            ReplayPolicy::NoCache => Ok(()),
            ReplayPolicy::RequireCache(cache) => cache.check_and_store(key, expires_at),
        }
    }

    pub(crate) fn check_and_store_message_replay_until(
        &mut self,
        key: ReplayKey,
        derived_deadline: Option<OffsetDateTime>,
    ) -> Result<(), SamlError> {
        let Some(deadline) = derived_deadline else {
            return self.check_and_store_message_replay(key);
        };
        let ReplayPolicy::RequireCache(cache) = &mut self.replay else {
            return Ok(());
        };
        let expires_at = system_time_from_offset_datetime(deadline)?;
        cache.check_and_store(key, expires_at)
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

pub(super) fn system_time_from_offset_datetime(
    deadline: OffsetDateTime,
) -> Result<SystemTime, SamlError> {
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
