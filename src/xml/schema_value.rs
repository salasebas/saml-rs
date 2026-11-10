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

/// Value of an `xs:unsignedShort` with surrounding XML whitespace.
pub(crate) fn xs_unsigned_short(value: &str) -> Option<u16> {
    value.trim_matches(XML_WHITESPACE).parse().ok()
}
