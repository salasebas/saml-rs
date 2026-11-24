use crate::constants::ParserType;
use crate::error::{SamlError, TimeWindowField};
use crate::model::ClockSkew;
use crate::util::Value;
use crate::xml::protocol_element::{parse_saml_with_limits, read_status};
use crate::xml::{fields, parse_saml_utc_instant, XmlLimits};
use std::time::SystemTime;
use time::{Duration, OffsetDateTime};

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

pub(crate) fn logout_request_not_on_or_after_deadline(
    extracted: &Value,
    now: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let Some(value) = extracted.get_str(fields::request::NOT_ON_OR_AFTER) else {
        return Ok(None);
    };
    let deadline = parse_saml_utc_instant(value).ok_or(SamlError::TimeWindowInvalid {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeWindow<'a> {
    pub(crate) not_before: Option<&'a str>,
    pub(crate) not_on_or_after: Option<&'a str>,
}

impl TimeWindow<'_> {
    pub(crate) fn contains(self, now: OffsetDateTime, skew: ClockSkew) -> bool {
        let not_before = self.not_before.map(parse_saml_utc_instant);
        let not_on_or_after = self.not_on_or_after.map(parse_saml_utc_instant);
        let begins_before_it_ends = not_before
            .flatten()
            .zip(not_on_or_after.flatten())
            .is_none_or(|(not_before, not_on_or_after)| not_before < not_on_or_after);
        let not_before_has_passed = not_before.is_none_or(|bound| {
            bound.is_some_and(|bound| not_before_has_elapsed(bound, skew.not_before_millis(), now))
        });
        let not_on_or_after_is_ahead = not_on_or_after.is_none_or(|bound| {
            bound.is_some_and(|bound| {
                not_on_or_after_is_open(bound, skew.not_on_or_after_millis(), now)
            })
        });
        begins_before_it_ends && not_before_has_passed && not_on_or_after_is_ahead
    }
}

fn shift_instant(instant: OffsetDateTime, drift_ms: i64) -> Option<OffsetDateTime> {
    instant.checked_add(Duration::milliseconds(drift_ms))
}

fn not_before_has_elapsed(bound: OffsetDateTime, drift_ms: i64, now: OffsetDateTime) -> bool {
    shift_instant(bound, drift_ms).is_some_and(|effective| effective <= now)
}

fn not_on_or_after_is_open(bound: OffsetDateTime, drift_ms: i64, now: OffsetDateTime) -> bool {
    match shift_instant(bound, drift_ms) {
        Some(effective) => now < effective,
        None => drift_ms >= 0,
    }
}

pub(crate) fn conditions_time_window(extracted: &Value) -> Result<TimeWindow<'_>, SamlError> {
    match extracted.get(fields::login_response::CONDITIONS) {
        None => Ok(TimeWindow {
            not_before: None,
            not_on_or_after: None,
        }),
        Some(Value::Array(items)) if items.is_empty() => Ok(TimeWindow {
            not_before: None,
            not_on_or_after: None,
        }),
        Some(conditions @ Value::Object(_)) => Ok(TimeWindow {
            not_before: conditions.get_str(fields::conditions::NOT_BEFORE),
            not_on_or_after: conditions.get_str(fields::conditions::NOT_ON_OR_AFTER),
        }),
        Some(Value::Array(_) | Value::Null | Value::Str(_)) => Err(SamlError::Invalid(
            "Assertion Conditions must be absent or occur exactly once".into(),
        )),
    }
}

pub fn check_status(
    content: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    match parser_type {
        ParserType::SamlResponse
        | ParserType::LogoutResponse
        | ParserType::ManageNameIdResponse => {
            read_status(&parse_saml_with_limits(content, limits)?)?.require_success()
        }
        ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::ManageNameIdRequest => {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SubordinateStatusCode, TopLevelStatusCode};
    use std::time::Duration as StdDuration;
    use time::format_description::well_known::Rfc3339;

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
        assert!(!window(None, Some("2000-01-01T00:00:00Z")).contains(now, strict));
        assert!(!window(Some("2999-01-01T00:00:00Z"), None).contains(now, strict));
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

        assert!(window(None, Some("2000-01-01T00:00:00Z"))
            .contains(now, ClockSkew::from_millis(0, 9_000_000_000_000)));
        assert!(window(Some("2999-01-01T00:00:00Z"), None)
            .contains(now, ClockSkew::from_millis(-50_000_000_000_000, 0)));
        Ok(())
    }

    #[test]
    fn skew_does_not_open_a_window_that_ends_before_it_begins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::parse("2026-10-10T00:00:00Z", &Rfc3339)?;
        let skew = ClockSkew::five_minutes();

        assert!(
            !window(Some("2026-10-10T00:00:00Z"), Some("2026-10-10T00:00:00Z")).contains(now, skew)
        );
        assert!(
            !window(Some("2026-10-10T00:01:00Z"), Some("2026-10-09T23:59:00Z")).contains(now, skew)
        );
        assert!(window(
            Some("2026-10-10T00:00:00Z"),
            Some("2026-10-10T00:00:00.001Z")
        )
        .contains(now, skew));
        Ok(())
    }

    #[test]
    fn status_success_and_two_tier_failure() -> Result<(), Box<dyn std::error::Error>> {
        check_status(RESPONSE, ParserType::SamlResponse, XmlLimits::default())?;
        check_status(RESPONSE, ParserType::SamlRequest, XmlLimits::default())?;

        match check_status(FAILED, ParserType::SamlResponse, XmlLimits::default()) {
            Err(SamlError::StatusNotSuccess { status, .. }) => {
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
    fn status_reads_one_status_with_one_top_level_status_code() {
        let success = r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#;
        let requester =
            r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>"#;
        let status = format!("<samlp:Status>{success}</samlp:Status>");
        let failed_status = format!("<samlp:Status>{requester}</samlp:Status>");
        let nested = |children: &str| {
            format!(
                r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">{children}</samlp:StatusCode></samlp:Status>"#
            )
        };
        for (parser_type, root) in [
            (ParserType::SamlResponse, "Response"),
            (ParserType::LogoutResponse, "LogoutResponse"),
            (ParserType::ManageNameIdResponse, "ManageNameIDResponse"),
        ] {
            let response = |children: &str| {
                format!(
                    r#"<samlp:{root} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">{children}</samlp:{root}>"#
                )
            };
            for children in [
                format!("{status}{failed_status}"),
                format!("<samlp:Status>{success}{requester}</samlp:Status>"),
                nested(r#"<samlp:StatusCode/>"#),
                nested(&format!("{requester}{requester}")),
            ] {
                let result = check_status(&response(&children), parser_type, XmlLimits::default());
                assert!(
                    matches!(result, Err(SamlError::ProtocolProfile(_))),
                    "{root} {children}: {result:?}"
                );
            }
            let accepted = check_status(&response(&status), parser_type, XmlLimits::default());
            assert!(accepted.is_ok(), "{root}: {accepted:?}");
        }
    }

    #[test]
    fn received_top_level_status_compares_the_any_uri_value() -> Result<(), SamlError> {
        let success = crate::constants::status_code::SUCCESS;
        let padded = RESPONSE.replace(success, &format!("&#9;{success} &#13;"));
        check_status(&padded, ParserType::SamlResponse, XmlLimits::default())?;

        let different = padded.replace(success, "urn:example:status:Success");
        assert!(matches!(
            check_status(&different, ParserType::SamlResponse, XmlLimits::default()),
            Err(SamlError::ProtocolProfile(_))
        ));

        for empty in ["", " &#9;"] {
            let xml = RESPONSE.replace(success, empty);
            let result = check_status(&xml, ParserType::SamlResponse, XmlLimits::default());
            assert!(
                matches!(result, Err(SamlError::StatusMissing)),
                "{result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn default_context_accepts_year_9999_not_on_or_after() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::model::{ReplayPolicy, SamlValidationContext};
        use std::time::SystemTime;

        let validation = SamlValidationContext::new(SystemTime::UNIX_EPOCH, ReplayPolicy::NoCache);
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
        assert!(
            !window(Some("9999-12-31T23:59:58Z"), Some(maximum)).contains(
                now,
                ClockSkew::from_millis(five_minutes_ms, five_minutes_ms)
            )
        );
        assert!(!window(None, Some("2020-01-01T00:00:00Z"))
            .contains(now, ClockSkew::from_millis(0, -1_000_000_000_000_000)));
        assert!(window(None, Some(maximum)).contains(now, ClockSkew::strict()));
        Ok(())
    }
}
