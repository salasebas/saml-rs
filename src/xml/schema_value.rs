//! Values of XML Schema built-in datatypes whose whitespace facet is
//! `collapse`, read after trimming XML whitespace.

const XML_WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];

/// Value of an unqualified `xs:boolean` attribute: `true`, `1`, `false`, or
/// `0`, with surrounding XML whitespace. Another lexical form is `None`.
pub(crate) fn xs_boolean(value: Option<&str>) -> Option<bool> {
    match value.map(|value| value.trim_matches(XML_WHITESPACE)) {
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) | None => None,
    }
}

/// Whether `value` is an `xs:integer` with surrounding XML whitespace: an
/// optional sign and one or more decimal digits.
pub(crate) fn is_xs_integer(value: &str) -> bool {
    let value = value.trim_matches(XML_WHITESPACE);
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_digit())
}

/// Value of an `xs:unsignedShort` with surrounding XML whitespace.
pub(crate) fn xs_unsigned_short(value: &str) -> Option<u16> {
    value.trim_matches(XML_WHITESPACE).parse().ok()
}
