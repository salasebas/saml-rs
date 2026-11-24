use super::*;
use saml_rs::error::{SubjectConfirmationReason, TimeWindowField};
use saml_rs::ClockSkew;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

const CONDITIONS: &str = "<saml:Conditions ";
const BEARER_DATA: &str = "<saml:SubjectConfirmationData ";
const STATEMENT: &str = "<saml:AuthnStatement ";

type ExpectedError = fn(&SamlError) -> bool;

fn attribute_range(
    xml: &str,
    element: &str,
    attribute: &str,
) -> Result<std::ops::Range<usize>, Box<dyn std::error::Error>> {
    let start = xml.find(element).ok_or("missing element")?;
    let tag_end = xml[start..].find('>').ok_or("unterminated element")? + start;
    let needle = format!(" {attribute}=\"");
    let value_start = xml[start..tag_end]
        .find(&needle)
        .ok_or("missing attribute")?
        + start
        + needle.len();
    let value_end = xml[value_start..]
        .find('"')
        .ok_or("unterminated attribute")?
        + value_start;
    Ok(value_start..value_end)
}

fn with_attribute_value(
    xml: &str,
    element: &str,
    attribute: &str,
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let range = attribute_range(xml, element, attribute)?;
    let mut replaced = xml.to_string();
    replaced.replace_range(range, value);
    Ok(replaced)
}

fn response_with_session_bound(exchange: &Exchange) -> Result<String, Box<dyn std::error::Error>> {
    let xml = response_xml(&exchange.response_fields)?;
    let bound = xml[attribute_range(&xml, CONDITIONS, "NotOnOrAfter")?].to_string();
    Ok(xml.replacen(
        STATEMENT,
        &format!("{STATEMENT}SessionNotOnOrAfter=\"{bound}\" "),
        1,
    ))
}

fn at_plus_one_hour(instant: OffsetDateTime) -> Result<String, Box<dyn std::error::Error>> {
    let local = instant.to_offset(UtcOffset::from_hms(1, 0, 0)?);
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+01:00",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute(),
        local.second()
    ))
}

#[test]
fn sso_time_bounds_reject_an_offset_form_of_an_accepted_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let conditions_rejected: ExpectedError = |error| {
        matches!(
            error,
            SamlError::TimeWindowInvalid {
                field: TimeWindowField::Conditions,
                ..
            }
        )
    };
    let cases: [(&str, &str, ExpectedError); 4] = [
        (CONDITIONS, "NotBefore", conditions_rejected),
        (CONDITIONS, "NotOnOrAfter", conditions_rejected),
        (BEARER_DATA, "NotOnOrAfter", |error| {
            matches!(
                error,
                SamlError::SubjectConfirmationInvalid {
                    reason: SubjectConfirmationReason::TimeWindowInvalid,
                    ..
                }
            )
        }),
        (STATEMENT, "SessionNotOnOrAfter", |error| {
            matches!(
                error,
                SamlError::TimeWindowInvalid {
                    field: TimeWindowField::SessionNotOnOrAfter,
                    ..
                }
            )
        }),
    ];
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let xml = response_with_session_bound(&exchange)?;
        accept(&exchange, &resigned(&xml)?)?;
        for (element, attribute, expected) in cases {
            let utc = &xml[attribute_range(&xml, element, attribute)?];
            let offset = at_plus_one_hour(OffsetDateTime::parse(utc, &Rfc3339)?)?;
            let replaced = with_attribute_value(&xml, element, attribute, &offset)?;
            expect_error(accept(&exchange, &resigned(&replaced)?), expected)
                .map_err(|error| format!("{attribute}=\"{offset}\": {error}"))?;
        }
    }
    Ok(())
}

#[test]
fn sso_time_bounds_are_reported_with_whitespace_collapsed() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let mut xml = response_with_session_bound(&exchange)?;
    let mut collapsed = Vec::new();
    for (element, attribute) in [
        (CONDITIONS, "NotBefore"),
        (CONDITIONS, "NotOnOrAfter"),
        (BEARER_DATA, "NotOnOrAfter"),
        (STATEMENT, "SessionNotOnOrAfter"),
    ] {
        let value = xml[attribute_range(&xml, element, attribute)?].to_string();
        xml = with_attribute_value(&xml, element, attribute, &format!(" {value} "))?;
        collapsed.push(value);
    }
    let [not_before, not_on_or_after, bearer, session_bound] = collapsed.as_slice() else {
        return Err("expected four bounds".into());
    };
    let mut cache = RecordingReplayCache::default();
    let session = accept_with(
        &exchange,
        &resigned(&xml)?,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(ClockSkew::strict()),
    )?;

    assert_eq!(
        (
            session.not_before().map(saml_rs::SamlInstant::as_str),
            session.not_on_or_after().map(saml_rs::SamlInstant::as_str),
            session
                .authn_statements()
                .iter()
                .map(|statement| statement
                    .session_not_on_or_after()
                    .map(saml_rs::SamlInstant::as_str))
                .collect::<Vec<_>>(),
        ),
        (
            Some(not_before.as_str()),
            Some(not_on_or_after.as_str()),
            vec![Some(session_bound.as_str())],
        )
    );
    let key = ReplayKey::Assertion(session.assertion_id().clone()).cache_key();
    assert_eq!(
        cache.seen.get(&key),
        Some(&SystemTime::from(OffsetDateTime::parse(bearer, &Rfc3339)?))
    );
    Ok(())
}

#[test]
fn replay_ignores_a_bearer_deadline_with_an_offset() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?;
    let confirmation_start = xml
        .find("<saml:SubjectConfirmation ")
        .ok_or("missing SubjectConfirmation")?;
    let end_tag = "</saml:SubjectConfirmation>";
    let confirmation_end = xml[confirmation_start..]
        .find(end_tag)
        .ok_or("unterminated SubjectConfirmation")?
        + confirmation_start
        + end_tag.len();
    let confirmation = &xml[confirmation_start..confirmation_end];
    let accepted =
        confirmation[attribute_range(confirmation, BEARER_DATA, "NotOnOrAfter")?].to_string();
    let later = OffsetDateTime::parse(&accepted, &Rfc3339)? + time::Duration::hours(1);
    let later_with_offset = at_plus_one_hour(later)?;
    let second = with_attribute_value(
        confirmation,
        BEARER_DATA,
        "NotOnOrAfter",
        &later_with_offset,
    )?;
    let mut two_confirmations = xml.clone();
    two_confirmations.insert_str(confirmation_end, &second);

    let mut cache = RecordingReplayCache::default();
    let session = accept_with(
        &exchange,
        &resigned(&two_confirmations)?,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(ClockSkew::strict()),
    )?;

    let key = ReplayKey::Assertion(session.assertion_id().clone()).cache_key();
    assert_eq!(
        cache.seen.get(&key),
        Some(&SystemTime::from(OffsetDateTime::parse(
            &accepted, &Rfc3339
        )?))
    );
    Ok(())
}
