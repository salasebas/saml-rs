use super::*;
use saml_rs::xml::dom::parse_qualified_document;

#[test]
fn async_slo_places_the_marker_inside_the_signed_request() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for (binding, children) in [
        (
            LogoutBinding::Redirect,
            &["Issuer", "Extensions", "NameID", "SessionIndex"][..],
        ),
        (
            LogoutBinding::Post,
            &[
                "Issuer",
                "Signature",
                "Extensions",
                "NameID",
                "SessionIndex",
            ][..],
        ),
    ] {
        let ordinary = sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
        let ordinary_xml = outbound_xml(&ordinary.outbound, "SAMLRequest")?;
        let ordinary_root = parse_document(&ordinary_xml, Default::default())?.root;
        assert!(ordinary_root.child_named("Extensions").is_none());

        let outbound =
            sp.start_async_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
        let xml = outbound_xml(&outbound, "SAMLRequest")?;
        let root = parse_qualified_document(&xml, Default::default())?;
        assert_eq!(
            root.children
                .iter()
                .map(|node| node.local_name.as_str())
                .collect::<Vec<_>>(),
            children,
        );
        let extensions = root
            .children
            .iter()
            .find(|node| node.local_name == "Extensions")
            .ok_or("missing Extensions")?;
        assert_eq!(extensions.namespace, "urn:oasis:names:tc:SAML:2.0:protocol");
        let [marker] = extensions.children.as_slice() else {
            return Err("expected one direct Extensions child".into());
        };
        assert_eq!(marker.local_name, "Asynchronous");
        assert_eq!(
            marker.namespace,
            "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo"
        );
        assert!(marker.attrs.is_empty() && marker.children.is_empty() && marker.text.is_empty());
        let received = idp.receive_slo(
            &sp_descriptor,
            logout_request_input(&outbound, binding)?,
            validation(),
        )?;
        assert_eq!(received.message().id(), outbound.id());
    }
    Ok(())
}

#[test]
fn async_slo_rejects_soap_and_simple_sign() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    for binding in [LogoutBinding::Soap, LogoutBinding::SimpleSign] {
        let result =
            sp.start_async_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding));
        assert!(matches!(
            result,
            Err(SamlError::UnsupportedBinding { binding: actual, .. }) if actual == binding.into()
        ));
    }
    Ok(())
}
