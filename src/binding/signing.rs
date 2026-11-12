use super::{append_signature, base64_encode, build_redirect_octet, build_simplesign_octet};
use crate::constants::{Binding, ParserType};
use crate::crypto::SigningCredential;
use crate::error::SamlError;

pub(crate) fn sign_detached_message(
    credential: &SigningCredential<'_>,
    binding: Binding,
    xml: &str,
    destination: &str,
    relay_state: Option<&str>,
    parser_type: ParserType,
    sig_alg: &str,
) -> Result<(String, Option<String>, Option<String>), SamlError> {
    match binding {
        Binding::Redirect => {
            let octet = build_redirect_octet(parser_type, xml, relay_state, sig_alg)?;
            let signature = credential.sign_detached(&octet, sig_alg)?;
            Ok((
                append_signature(destination, &octet, &signature),
                None,
                None,
            ))
        }
        Binding::SimpleSign => {
            let octet =
                build_simplesign_octet(parser_type.query_param(), xml, relay_state, sig_alg);
            let signature = credential.sign_detached(&octet, sig_alg)?;
            Ok((
                base64_encode(xml.as_bytes()),
                Some(signature),
                Some(sig_alg.to_string()),
            ))
        }
        Binding::Post | Binding::Artifact | Binding::Soap => {
            Err(SamlError::UnsupportedBinding { binding })
        }
    }
}
