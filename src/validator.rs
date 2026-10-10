//! SAML time-window and status validation.

use crate::constants::{status_code, ParserType};
use crate::error::{SamlError, TimeWindowField};
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

/// Validate a `NotBefore` / `NotOnOrAfter` window.
///
/// `drift` is `(not_before_ms, not_on_or_after_ms)` added to the respective
/// bounds. When neither bound is present the document is treated as valid.
/// A present-but-unparseable timestamp fails closed (mirrors JS `Invalid Date`).
/// A `NotOnOrAfter` bound whose skew passes the maximum supported instant is
/// treated as not expired. A `NotBefore` bound that cannot be shifted inside
/// the supported range fails closed.
pub fn verify_time(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
) -> bool {
    verify_time_at(
        not_before,
        not_on_or_after,
        drift,
        OffsetDateTime::now_utc(),
    )
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

pub(crate) fn verify_time_at(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
    now: OffsetDateTime,
) -> bool {
    let (not_before_ms, not_on_or_after_ms) = drift;

    match (not_before, not_on_or_after) {
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

pub(crate) fn conditions_time_bounds(
    extracted: &Value,
) -> Result<(Option<&str>, Option<&str>), SamlError> {
    match extracted.get("conditions") {
        None => Ok((None, None)),
        Some(Value::Array(items)) if items.is_empty() => Ok((None, None)),
        Some(conditions @ Value::Object(_)) => Ok((
            conditions.get_str("notBefore"),
            conditions.get_str("notOnOrAfter"),
        )),
        Some(Value::Array(_) | Value::Null | Value::Str(_)) => Err(SamlError::Invalid(
            "Assertion Conditions must be absent or occur exactly once".into(),
        )),
    }
}

/// Check the two-tier `<StatusCode>` of a response.
///
/// Only `SAMLResponse` / `LogoutResponse` are checked; other parser types are
/// skipped. Success resolves to `Ok(())`; anything else is an error.
pub fn check_status(content: &str, parser_type: ParserType) -> Result<(), SamlError> {
    check_status_with_limits(content, parser_type, XmlLimits::default())
}

/// Check response status with explicit XML parser resource limits.
pub fn check_status_with_limits(
    content: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let fields = match parser_type {
        ParserType::SamlResponse => fields::login_response_status_fields(),
        ParserType::LogoutResponse => fields::logout_response_status_fields(),
        _ => return Ok(()),
    };
    let result = extract_with_limits(content, &fields, limits)?;
    match result.get_str("top") {
        Some(code) if code == status_code::SUCCESS => Ok(()),
        Some(code) if !code.is_empty() => Err(SamlError::StatusNotSuccess {
            top: code.to_string(),
            second: result
                .get_str("second")
                .filter(|second| !second.is_empty())
                .map(str::to_string),
        }),
        _ => Err(SamlError::UndefinedStatus),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    const RESPONSE: &str = include_str!("../tests/fixtures/response.xml");
    const FAILED: &str = include_str!("../tests/fixtures/failed_response.xml");

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

    #[test]
    fn time_window_basic() {
        assert!(verify_time(None, None, (0, 0)));
        assert!(verify_time(
            Some("2000-01-01T00:00:00Z"),
            Some("2999-01-01T00:00:00Z"),
            (0, 0)
        ));
        // expired
        assert!(!verify_time(None, Some("2000-01-01T00:00:00Z"), (0, 0)));
        // not yet valid
        assert!(!verify_time(Some("2999-01-01T00:00:00Z"), None, (0, 0)));
        // unparseable fails closed
        assert!(!verify_time(Some("not-a-date"), None, (0, 0)));
    }

    #[test]
    fn absent_conditions_remain_unbounded() -> Result<(), Box<dyn std::error::Error>> {
        let extracted = Value::Object(vec![("conditions".into(), Value::Array(Vec::new()))]);

        assert_eq!(conditions_time_bounds(&extracted)?, (None, None));
        Ok(())
    }

    #[test]
    fn drift_widens_window() {
        // expired, but a huge positive notOnOrAfter drift makes it valid again
        assert!(verify_time(
            None,
            Some("2000-01-01T00:00:00Z"),
            (0, 9_000_000_000_000)
        ));
        // not-yet-valid, but a huge negative notBefore drift makes it valid
        assert!(verify_time(
            Some("2999-01-01T00:00:00Z"),
            None,
            (-50_000_000_000_000, 0)
        ));
    }

    #[test]
    fn status_success_and_two_tier_failure() -> Result<(), Box<dyn std::error::Error>> {
        check_status(RESPONSE, ParserType::SamlResponse)?;
        // request types are skipped
        check_status(RESPONSE, ParserType::SamlRequest)?;

        match check_status(FAILED, ParserType::SamlResponse) {
            Err(SamlError::StatusNotSuccess { top, second }) => {
                assert_eq!(top, status_code::REQUESTER);
                assert_eq!(second.as_deref(), Some(status_code::INVALID_NAME_ID_POLICY));
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

        let validation = SamlValidationContext::new(
            SystemTime::UNIX_EPOCH,
            ReplayPolicy::DisabledForCompatibility,
        );
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let drift = validation.clock_skew().as_millis();
        let never_expires = "9999-12-31T23:59:59Z";

        assert!(verify_time(None, Some(never_expires), drift));
        assert!(verify_time_at(None, Some(never_expires), drift, now));
        assert!(verify_time_at(
            Some("2014-07-17T01:01:18Z"),
            Some(never_expires),
            drift,
            now,
        ));
        assert!(!verify_time_at(Some(never_expires), None, drift, now));
        Ok(())
    }

    #[test]
    fn unrepresentable_time_shift_follows_the_window_bounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let maximum = "9999-12-31T23:59:59Z";
        let five_minutes_ms = 5 * 60 * 1000;

        assert!(!verify_time_at(
            Some(maximum),
            None,
            (five_minutes_ms, 0),
            now,
        ));
        assert!(!verify_time_at(
            Some(maximum),
            Some(maximum),
            (five_minutes_ms, five_minutes_ms),
            now,
        ));
        assert!(!verify_time_at(
            None,
            Some("2020-01-01T00:00:00Z"),
            (0, -1_000_000_000_000_000),
            now,
        ));
        assert!(verify_time_at(None, Some(maximum), (0, 0), now));
        Ok(())
    }
}
