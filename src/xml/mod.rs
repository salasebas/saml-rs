//! XML parsing and field extraction over quick-xml.

pub(crate) mod any_uri;
mod date_time;
pub mod dom;
pub mod extract;
pub(crate) mod fields;
pub(crate) mod fragment;
pub(crate) mod name;
mod profile;
pub(crate) mod protocol_element;
mod schema_value;
pub(crate) mod signature_placement;
pub(crate) mod write;

pub(crate) use date_time::{
    parse_generated_saml_utc_date_time, parse_saml_utc_date_time, parse_timezoned_date_time,
};
pub use dom::XmlLimits;
pub use extract::{extract, extract_with_limits, ExtractorField, LocalPath};
pub(crate) use profile::{
    validate_logout_request_outbound, validate_logout_response_outbound, validate_protocol_profile,
    OutboundLogoutExpiration, OutboundLogoutRequestExpectation, OutboundLogoutRequestValidation,
    OutboundLogoutValidation, OutboundNameIdQualifiers,
};
pub(crate) use schema_value::{xs_boolean, xs_unsigned_short};

/// Length of the UTF-8 byte order mark that starts `xml`, or 0.
///
/// quick-xml skips a leading byte order mark without counting it, so
/// `Reader::buffer_position` is this many bytes behind the source offset.
pub(crate) fn utf8_bom_len(xml: &str) -> usize {
    const BOM: char = '\u{feff}';
    if xml.starts_with(BOM) {
        BOM.len_utf8()
    } else {
        0
    }
}

pub(crate) fn is_xml_char(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..
    )
}
