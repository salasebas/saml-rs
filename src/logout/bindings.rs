use crate::binding::{build_redirect_url, encode_base64};
use crate::constants::{Binding, ParserType};
use crate::error::SamlError;

pub(crate) fn unsigned_context(
    binding: Binding,
    xml: &str,
    destination: &str,
    parser_type: ParserType,
    relay: Option<&str>,
) -> Result<String, SamlError> {
    match binding {
        Binding::Redirect => build_redirect_url(destination, parser_type, xml, relay),
        Binding::Post | Binding::SimpleSign => Ok(encode_base64(xml.as_bytes())),
        Binding::Soap => Ok(xml.to_string()),
        Binding::Artifact => Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        }),
    }
}
