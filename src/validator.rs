//! SAML time-window and status validation.

use crate::constants::ParserType;
use crate::error::{SamlError, TimeWindowField};
use crate::model::{ClockSkew, Status};
use crate::util::Value;
use crate::xml::{extract_with_limits, fields, parse_saml_utc_date_time, XmlLimits};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

fn parse(ts: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).ok()
}

pub(crate) fn offset_datetime_from_system_time(
    instant: SystemTime,
) -> Result<OffsetDateTime, SamlError> {
    let converted = match instant.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => Duration::try_from(elapsed)
            .ok()
            .and_then(|elapsed| OffsetDateTime::UNIX_EPOCH.checked_add(elapsed)),
        Err(error) => Duration::try_from(error.duration())
            .ok()
            .and_then(|elapsed| OffsetDateTime::UNIX_EPOCH.checked_sub(elapsed)),
    };
    converted.ok_or_else(|| {
        SamlError::Invalid("validation instant is outside the supported SAML time range".into())
    })
}

/// Validate saml-rs' fail-closed expiration policy for an inbound LogoutRequest.
///
/// The protocol profile layer owns SAML lexical conformance. Values that are
/// lexically valid but cannot be represented by the runtime clock fail here as
/// a library time-window policy decision.
pub(crate) fn logout_request_not_on_or_after_deadline(
    extracted: &Value,
    now: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let Some(value) = extracted.get_str("request.notOnOrAfter") else {
        return Ok(None);
    };
    let normalized = parse_saml_utc_date_time(value).ok_or(SamlError::TimeWindowInvalid {
        field: TimeWindowField::LogoutRequestNotOnOrAfter,
    })?;
    let deadline =
        OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        })?;
    let effective_deadline = effective_not_on_or_after(deadline, not_on_or_after_skew_ms)?;
    if now >= effective_deadline {
        return Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        });
    }
    Ok(Some(effective_deadline))
}

/// `NotOnOrAfter` plus the validation context's `NotOnOrAfter` clock skew.
pub(crate) fn effective_not_on_or_after(
    deadline: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<OffsetDateTime, SamlError> {
    deadline
        .checked_add(Duration::milliseconds(not_on_or_after_skew_ms))
        .ok_or(SamlError::TimeWindowInvalid {
            field: TimeWindowField::LogoutRequestNotOnOrAfter,
        })
}

/// The `NotBefore` and `NotOnOrAfter` attributes of one element, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeWindow<'a> {
    pub(crate) not_before: Option<&'a str>,
    pub(crate) not_on_or_after: Option<&'a str>,
}

impl TimeWindow<'_> {
    /// Whether `now` falls inside the window widened by `skew`.
    ///
    /// The `NotBefore` skew and the `NotOnOrAfter` skew are added to their
    /// bounds. When neither bound is present the window contains every
    /// instant. A present-but-unparseable timestamp fails closed (mirrors JS
    /// `Invalid Date`). A `NotOnOrAfter` bound whose skew passes the maximum
    /// supported instant is treated as not expired, and one whose skew passes
    /// the minimum supported instant is treated as expired. A `NotBefore` bound
    /// that cannot be shifted inside the supported range fails closed.
    pub(crate) fn contains(self, now: OffsetDateTime, skew: ClockSkew) -> bool {
        let not_before_ms = skew.not_before_millis();
        let not_on_or_after_ms = skew.not_on_or_after_millis();

        match (self.not_before, self.not_on_or_after) {
            (None, None) => true,
            (Some(not_before), None) => match parse(not_before) {
                Some(bound) => not_before_has_elapsed(bound, not_before_ms, now),
                None => false,
            },
            (None, Some(not_on_or_after)) => match parse(not_on_or_after) {
                Some(bound) => not_on_or_after_is_open(bound, not_on_or_after_ms, now),
                None => false,
            },
            (Some(not_before), Some(not_on_or_after)) => {
                match (parse(not_before), parse(not_on_or_after)) {
                    (Some(not_before), Some(not_on_or_after)) => {
                        not_before_has_elapsed(not_before, not_before_ms, now)
                            && not_on_or_after_is_open(not_on_or_after, not_on_or_after_ms, now)
                    }
                    _ => false,
                }
            }
        }
    }
}

fn shift_instant(instant: OffsetDateTime, drift_ms: i64) -> Option<OffsetDateTime> {
    instant.checked_add(Duration::milliseconds(drift_ms))
}

fn not_before_has_elapsed(bound: OffsetDateTime, drift_ms: i64, now: OffsetDateTime) -> bool {
    shift_instant(bound, drift_ms).is_some_and(|effective| effective <= now)
}

/// `NotOnOrAfter` is exclusive.
///
/// A positive skew that passes the maximum supported instant is still after
/// every representable `now`. A negative skew that passes the minimum
/// supported instant is before every representable `now`.
fn not_on_or_after_is_open(bound: OffsetDateTime, drift_ms: i64, now: OffsetDateTime) -> bool {
    match shift_instant(bound, drift_ms) {
        Some(effective) => now < effective,
        None => drift_ms >= 0,
    }
}

pub(crate) fn conditions_time_window(extracted: &Value) -> Result<TimeWindow<'_>, SamlError> {
    match extracted.get("conditions") {
        None => Ok(TimeWindow {
            not_before: None,
            not_on_or_after: None,
        }),
        Some(Value::Array(items)) if items.is_empty() => Ok(TimeWindow {
            not_before: None,
            not_on_or_after: None,
        }),
        Some(conditions @ Value::Object(_)) => Ok(TimeWindow {
            not_before: conditions.get_str("notBefore"),
            not_on_or_after: conditions.get_str("notOnOrAfter"),
        }),
        Some(Value::Array(_) | Value::Null | Value::Str(_)) => Err(SamlError::Invalid(
            "Assertion Conditions must be absent or occur exactly once".into(),
        )),
    }
}

/// Check the two-tier `<StatusCode>` of a response, parsing `content` under
/// `limits`.
///
/// Only `SAMLResponse`, `LogoutResponse`, and `ManageNameIDResponse` are
/// checked; request parser types are skipped. Success resolves to `Ok(())`;
/// anything else is an error.
pub fn check_status(
    content: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let fields = match parser_type {
        ParserType::SamlResponse => fields::login_response_status_fields(),
        ParserType::LogoutResponse => fields::logout_response_status_fields(),
        ParserType::ManageNameIdResponse => fields::manage_name_id_response_status_fields(),
        ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::ManageNameIdRequest => {
            return Ok(())
        }
    };
    let result = extract_with_limits(content, &fields, limits)?;
    let top = result
        .get_str("top")
        .filter(|top| !top.is_empty())
        .ok_or(SamlError::StatusMissing)?;
    Status::received(top, result.get_str("second"))?.require_success()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SubordinateStatusCode, TopLevelStatusCode};
    use std::time::Duration as StdDuration;

    const RESPONSE: &str = include_str!("../tests/fixtures/misc/response.xml");
    const FAILED: &str = include_str!("../tests/fixtures/misc/failed_response.xml");

    #[test]
    fn system_time_conversion_supports_pre_unix_epoch() -> Result<(), Box<dyn std::error::Error>> {
        let instant = SystemTime::UNIX_EPOCH
            .checked_sub(StdDuration::new(1, 7))
            .ok_or("platform SystemTime cannot represent the test instant")?;

        assert_eq!(
            offset_datetime_from_system_time(instant)?.unix_timestamp_nanos(),
            -1_000_000_007
        );
        Ok(())
    }

    #[test]
    fn system_time_conversion_preserves_nanoseconds() -> Result<(), Box<dyn std::error::Error>> {
        let instant = SystemTime::UNIX_EPOCH
            .checked_add(StdDuration::new(1, 234_567_890))
            .ok_or("platform SystemTime cannot represent the test instant")?;

        assert_eq!(
            offset_datetime_from_system_time(instant)?.unix_timestamp_nanos(),
            1_234_567_890
        );
        Ok(())
    }

    fn window<'a>(not_before: Option<&'a str>, not_on_or_after: Option<&'a str>) -> TimeWindow<'a> {
        TimeWindow {
            not_before,
            not_on_or_after,
        }
    }

    #[test]
    fn time_window_basic() -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let strict = ClockSkew::strict();

        assert!(window(None, None).contains(now, strict));
        assert!(
            window(Some("2000-01-01T00:00:00Z"), Some("2999-01-01T00:00:00Z"))
                .contains(now, strict)
        );
        // expired
        assert!(!window(None, Some("2000-01-01T00:00:00Z")).contains(now, strict));
        // not yet valid
        assert!(!window(Some("2999-01-01T00:00:00Z"), None).contains(now, strict));
        // unparseable fails closed
        assert!(!window(Some("not-a-date"), None).contains(now, strict));
        Ok(())
    }

    #[test]
    fn absent_conditions_remain_unbounded() -> Result<(), Box<dyn std::error::Error>> {
        let extracted = Value::Object(vec![("conditions".into(), Value::Array(Vec::new()))]);

        assert_eq!(conditions_time_window(&extracted)?, window(None, None));
        Ok(())
    }

    #[test]
    fn drift_widens_window() -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;

        // expired, but a huge positive notOnOrAfter drift makes it valid again
        assert!(window(None, Some("2000-01-01T00:00:00Z"))
            .contains(now, ClockSkew::from_millis(0, 9_000_000_000_000)));
        // not-yet-valid, but a huge negative notBefore drift makes it valid
        assert!(window(Some("2999-01-01T00:00:00Z"), None)
            .contains(now, ClockSkew::from_millis(-50_000_000_000_000, 0)));
        Ok(())
    }

    #[test]
    fn status_success_and_two_tier_failure() -> Result<(), Box<dyn std::error::Error>> {
        check_status(RESPONSE, ParserType::SamlResponse, XmlLimits::default())?;
        // request types are skipped
        check_status(RESPONSE, ParserType::SamlRequest, XmlLimits::default())?;

        match check_status(FAILED, ParserType::SamlResponse, XmlLimits::default()) {
            Err(SamlError::StatusNotSuccess { status }) => {
                assert_eq!(status.top_level(), TopLevelStatusCode::Requester);
                assert_eq!(
                    status.subordinate().map(SubordinateStatusCode::as_uri),
                    Some(crate::constants::status_code::INVALID_NAME_ID_POLICY)
                );
            }
            other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn default_context_accepts_year_9999_not_on_or_after() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::model::{ReplayPolicy, SamlValidationContext};
        use std::time::SystemTime;

        let validation = SamlValidationContext::new(SystemTime::UNIX_EPOCH, ReplayPolicy::Disabled);
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let skew = validation.clock_skew();
        let never_expires = "9999-12-31T23:59:59Z";

        assert!(window(None, Some(never_expires)).contains(now, skew));
        assert!(window(Some("2014-07-17T01:01:18Z"), Some(never_expires)).contains(now, skew));
        assert!(!window(Some(never_expires), None).contains(now, skew));
        Ok(())
    }

    #[test]
    fn unrepresentable_time_shift_follows_the_window_bounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let maximum = "9999-12-31T23:59:59Z";
        let five_minutes_ms = 5 * 60 * 1000;

        assert!(
            !window(Some(maximum), None).contains(now, ClockSkew::from_millis(five_minutes_ms, 0))
        );
        assert!(!window(Some(maximum), Some(maximum)).contains(
            now,
            ClockSkew::from_millis(five_minutes_ms, five_minutes_ms)
        ));
        assert!(!window(None, Some("2020-01-01T00:00:00Z"))
            .contains(now, ClockSkew::from_millis(0, -1_000_000_000_000_000)));
        assert!(window(None, Some(maximum)).contains(now, ClockSkew::strict()));
        Ok(())
    }
}
