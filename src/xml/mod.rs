//! XML parsing and field extraction over quick-xml.

mod date_time;
pub mod dom;
pub mod extract;
pub mod fields;
pub(crate) mod fragment;
mod profile;
pub(crate) mod write;

pub(crate) use date_time::{parse_generated_saml_utc_date_time, parse_saml_utc_date_time};
pub use dom::XmlLimits;
pub use extract::{extract, extract_with_limits, ExtractorField, LocalPath};
pub(crate) use profile::{
    validate_logout_request_outbound, validate_logout_response_outbound, validate_protocol_profile,
    OutboundLogoutExpiration, OutboundLogoutRequestExpectation, OutboundLogoutRequestValidation,
    OutboundLogoutValidation, OutboundNameIdQualifiers,
};
