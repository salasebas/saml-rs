use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{push_normalized_namespaces, reader_err};
use quick_xml::events::Event;
use quick_xml::name::{Namespace, NamespaceResolver, ResolveResult};
use quick_xml::Reader;

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

pub(crate) fn root_uses_protocol_response_rules(xml: &str) -> Result<bool, SamlError> {
    let mut reader = Reader::from_str(xml);
    loop {
        match reader.read_event().map_err(reader_err)? {
            Event::Start(element) | Event::Empty(element) => {
                let mut resolver = NamespaceResolver::default();
                push_normalized_namespaces(&mut resolver, &element)?;
                let (resolved, local_name) = resolver.resolve_element(element.name());
                return Ok(matches!(
                    resolved,
                    ResolveResult::Bound(Namespace(namespace::PROTOCOL))
                ) && is_protocol_response_name(local_name.as_ref()));
            }
            Event::Eof => return Err(SamlError::xml("no document element")),
            _ => {}
        }
    }
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
        assert!(root_uses_protocol_response_rules(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protoco&#108;"/>"#
        )?);
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
