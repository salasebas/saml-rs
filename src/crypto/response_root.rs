//! Recognition of SAML protocol response document elements.

use crate::constants::namespace;
use crate::error::SamlError;
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;

/// Protocol-namespace local names that use response coverage and wrapping checks.
fn is_protocol_response_name(local_name: &str) -> bool {
    matches!(
        local_name,
        "Response"
            | "ArtifactResponse"
            | "LogoutResponse"
            | "ManageNameIDResponse"
            | "NameIDMappingResponse"
    )
}

fn document_element_name(xml: &str) -> Result<(String, String), SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                let (resolved, local_name) = reader.resolver().resolve_element(element.name());
                let local_name = local_name.as_ref().to_string();
                let resolved = match resolved {
                    ResolveResult::Bound(Namespace(uri)) => uri.to_string(),
                    ResolveResult::Unbound | ResolveResult::Unknown(_) => String::new(),
                };
                return Ok((resolved, local_name));
            }
            Ok(Event::Eof) => {
                return Err(SamlError::Xml("no document element".into()));
            }
            Ok(_) => {}
            Err(error) => return Err(SamlError::Xml(error.to_string())),
        }
        buffer.clear();
    }
}

/// Whether the document element is a SAML protocol response that takes the
/// response coverage and wrapping checks.
pub(crate) fn root_uses_protocol_response_rules(xml: &str) -> Result<bool, SamlError> {
    let (element_namespace, local_name) = document_element_name(xml)?;
    Ok(element_namespace == namespace::PROTOCOL && is_protocol_response_name(&local_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_response_roots_match_exact_namespace_aware_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let protocol = namespace::PROTOCOL;
        for local_name in [
            "Response",
            "ArtifactResponse",
            "LogoutResponse",
            "ManageNameIDResponse",
            "NameIDMappingResponse",
        ] {
            let prefixed = format!(r#"<samlp:{local_name} xmlns:samlp="{protocol}"/>"#);
            let default_namespace = format!(r#"<{local_name} xmlns="{protocol}"/>"#);
            assert!(
                root_uses_protocol_response_rules(&prefixed)?,
                "{local_name}"
            );
            assert!(
                root_uses_protocol_response_rules(&default_namespace)?,
                "{local_name}"
            );
        }

        let prologue = format!(
            "<?xml version=\"1.0\"?><!-- before --><samlp:Response xmlns:samlp=\"{protocol}\"/>"
        );
        assert!(root_uses_protocol_response_rules(&prologue)?);
        assert!(!root_uses_protocol_response_rules(
            r#"<samlp:Response xmlns:samlp="urn:example:not-saml"/>"#
        )?);
        assert!(!root_uses_protocol_response_rules(&format!(
            r#"<samlp:FooResponse xmlns:samlp="{protocol}"/>"#
        ))?);
        assert!(!root_uses_protocol_response_rules(&format!(
            r#"<samlp:LogoutRequest xmlns:samlp="{protocol}"/>"#
        ))?);
        assert!(!root_uses_protocol_response_rules(
            "<samlp:Response>x</samlp:Response>"
        )?);
        Ok(())
    }
}
