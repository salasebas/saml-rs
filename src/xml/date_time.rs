fn parse_two_ascii_digits(value: &[u8], offset: usize) -> Option<u8> {
    let tens = value.get(offset)?.checked_sub(b'0')?;
    let ones = value.get(offset + 1)?.checked_sub(b'0')?;
    (tens <= 9 && ones <= 9).then(|| tens * 10 + ones)
}

fn year_modulo(year: &[u8], modulus: u16) -> Option<u16> {
    year.iter().try_fold(0, |remainder, digit| {
        let digit = digit.checked_sub(b'0')?;
        (digit <= 9).then_some((remainder * 10 + u16::from(digit)) % modulus)
    })
}

fn signed_year_modulo(year: &[u8], negative: bool, modulus: u16) -> Option<u16> {
    let magnitude = year_modulo(year, modulus)?;
    if negative {
        // XML Schema 1.0 has no year zero: -0001 is 1 BCE, whose
        // astronomical year is 0. In general, -N maps to 1 - N.
        Some((modulus + 1 - magnitude) % modulus)
    } else {
        Some(magnitude)
    }
}

fn is_leap_year(year: &[u8], negative: bool) -> bool {
    matches!(signed_year_modulo(year, negative, 400), Some(0))
        || (matches!(signed_year_modulo(year, negative, 4), Some(0))
            && !matches!(signed_year_modulo(year, negative, 100), Some(0)))
}

fn is_valid_calendar_day(year: &[u8], negative_year: bool, month: u8, day: u8) -> bool {
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year, negative_year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_xml_schema_whitespace(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\n' | '\r')
}

/// Parse the SAML UTC subset of `xs:dateTime` and return its collapsed value.
pub(crate) fn parse_saml_utc_date_time(value: &str) -> Option<&str> {
    parse_saml_utc_date_time_with_seconds(value).map(|(normalized, _)| normalized)
}

/// Parse a UTC `xs:dateTime` that a SAML producer is allowed to generate.
pub(crate) fn parse_generated_saml_utc_date_time(value: &str) -> Option<&str> {
    parse_saml_utc_date_time_with_seconds(value)
        .filter(|(_, second)| *second < 60)
        .map(|(normalized, _)| normalized)
}

fn parse_saml_utc_date_time_with_seconds(value: &str) -> Option<(&str, u8)> {
    let value = value.trim_matches(is_xml_schema_whitespace);
    let without_timezone = value.strip_suffix('Z')?;
    let bytes = without_timezone.as_bytes();
    let negative_year = bytes.first() == Some(&b'-');
    let year_start = usize::from(negative_year);
    let year_separator = bytes
        .get(year_start..)?
        .iter()
        .position(|byte| *byte == b'-')
        .map(|offset| year_start + offset)?;
    let year = &bytes[year_start..year_separator];
    if year.len() < 4
        || (year.len() > 4 && year.first() == Some(&b'0'))
        || year.iter().all(|digit| *digit == b'0')
        || year_modulo(year, 400).is_none()
    {
        return None;
    }

    let time_end = year_separator + 15;
    if bytes.len() < time_end
        || bytes.get(year_separator) != Some(&b'-')
        || bytes.get(year_separator + 3) != Some(&b'-')
        || bytes.get(year_separator + 6) != Some(&b'T')
        || bytes.get(year_separator + 9) != Some(&b':')
        || bytes.get(year_separator + 12) != Some(&b':')
    {
        return None;
    }

    let month = parse_two_ascii_digits(bytes, year_separator + 1)?;
    let day = parse_two_ascii_digits(bytes, year_separator + 4)?;
    let hour = parse_two_ascii_digits(bytes, year_separator + 7)?;
    let minute = parse_two_ascii_digits(bytes, year_separator + 10)?;
    let second = parse_two_ascii_digits(bytes, year_separator + 13)?;
    // XML Schema permits second 60. SAML Core 2.0 §1.3.3 forbids producers
    // from generating leap seconds but does not require receivers to reject them.
    if !is_valid_calendar_day(year, negative_year, month, day) || minute > 59 || second > 60 {
        return None;
    }

    let fractional = &bytes[time_end..];
    let valid_fractional = fractional.is_empty()
        || (fractional.first() == Some(&b'.')
            && fractional.len() > 1
            && fractional[1..].iter().all(u8::is_ascii_digit));
    if !valid_fractional {
        return None;
    }

    (hour < 24
        || (hour == 24
            && minute == 0
            && second == 0
            && fractional
                .get(1..)
                .is_none_or(|digits| digits.iter().all(|digit| *digit == b'0'))))
    .then_some((value, second))
}

#[cfg(test)]
mod tests {
    use super::{parse_generated_saml_utc_date_time, parse_saml_utc_date_time};

    #[test]
    fn accepts_and_normalizes_saml_utc_date_times() {
        let cases = [
            ("2004-02-29T23:59:59Z", "2004-02-29T23:59:59Z"),
            ("2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z"),
            ("2024-01-01T00:00:60Z", "2024-01-01T00:00:60Z"),
            ("-0001-02-29T00:00:00Z", "-0001-02-29T00:00:00Z"),
            ("-0401-02-29T00:00:00Z", "-0401-02-29T00:00:00Z"),
            (
                "-100000000000000000000000000000000000000001-02-29T00:00:00Z",
                "-100000000000000000000000000000000000000001-02-29T00:00:00Z",
            ),
            ("2024-01-01T24:00:00Z", "2024-01-01T24:00:00Z"),
            ("2024-01-01T24:00:00.000Z", "2024-01-01T24:00:00.000Z"),
            (
                " \t\n\r2024-01-01T00:00:00.123Z \t\n\r",
                "2024-01-01T00:00:00.123Z",
            ),
        ];

        for (value, normalized) in cases {
            assert_eq!(parse_saml_utc_date_time(value), Some(normalized));
        }
    }

    #[test]
    fn accepts_xml_schema_leap_seconds_inbound() {
        assert_eq!(
            parse_saml_utc_date_time("2024-01-01T00:00:60Z"),
            Some("2024-01-01T00:00:60Z")
        );
    }

    #[test]
    fn rejects_invalid_calendar_and_time_boundaries() {
        for value in [
            "1900-02-29T00:00:00Z",
            "-0002-02-29T00:00:00Z",
            "-0101-02-29T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "01234-01-01T00:00:00Z",
            "2024-00-01T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-00T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-01-01T00:60:00Z",
            "2024-01-01T00:00:61Z",
            "2024-01-01T24:01:00Z",
            "2024-01-01T24:00:01Z",
            "2024-01-01T25:00:00Z",
        ] {
            assert_eq!(parse_saml_utc_date_time(value), None, "{value}");
        }
    }

    #[test]
    fn rejects_invalid_lexical_and_whitespace_forms() {
        for value in [
            "2024-01-01T00:00:00",
            "+2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00.\u{0661}Z",
            "2024-01-01T00:00:00.1suffixZ",
            "2024-01-01T00:00:00Zsuffix",
            "\u{00a0}2024-01-01T00:00:00Z\u{00a0}",
        ] {
            assert_eq!(parse_saml_utc_date_time(value), None, "{value:?}");
        }
    }

    #[test]
    fn generated_saml_date_time_rejects_leap_seconds() {
        assert_eq!(
            parse_generated_saml_utc_date_time("2024-01-01T00:00:60Z"),
            None
        );
    }
}
