use super::*;
use saml_rs::xml::dom::parse_qualified_document;
use saml_rs::IdpLogoutAction;

const ASYNC_NAMESPACE: &str = "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo";

#[test]
fn async_slo_routes_a_signed_sp_request_to_local_completion(
) -> Result<(), Box<dyn std::error::Error>> {
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
        let IdpLogoutAction::Respond(request) = idp.receive_slo_with_async(
            &sp_descriptor,
            logout_request_input(&ordinary.outbound, binding)?,
            validation(),
        )?
        else {
            return Err(format!("ordinary {binding:?} logout requires a response").into());
        };
        let response = idp.respond_slo(
            &sp_descriptor,
            &request,
            &Status::success(),
            respond_slo_for_binding(binding),
        )?;
        sp.finish_slo(
            &idp_descriptor,
            &ordinary.pending,
            logout_response_input(&response, binding)?,
            validation(),
        )?;

        let subject = subject()?;
        let outbound = sp.start_async_slo(
            &idp_descriptor,
            subject.clone(),
            start_slo_for_binding(binding),
        )?;
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
        assert_eq!(marker.namespace, ASYNC_NAMESPACE);
        assert!(marker.attrs.is_empty() && marker.children.is_empty() && marker.text.is_empty());

        let ordinary_receipt = idp.receive_slo(
            &sp_descriptor,
            logout_request_input(&outbound, binding)?,
            validation(),
        )?;
        assert_eq!(ordinary_receipt.message().id(), outbound.id());

        let mut cache = RecordingReplayCache::default();
        let IdpLogoutAction::CompleteLocally(request) = idp.receive_slo_with_async(
            &sp_descriptor,
            logout_request_input(&outbound, binding)?,
            validation_with_cache(&mut cache),
        )?
        else {
            return Err(format!("asynchronous {binding:?} logout must finish locally").into());
        };
        assert_eq!(request.id(), outbound.id());
        assert_eq!(request.issuer().as_str(), SP_ENTITY_ID);
        assert_eq!(request.name_id(), Some(subject.name_id()));
        assert_eq!(request.session_indexes(), subject.session_indexes());
        assert!(matches!(
            idp.receive_slo_with_async(
                &sp_descriptor,
                logout_request_input(&outbound, binding)?,
                validation_with_cache(&mut cache),
            ),
            Err(SamlError::ReplayDetected { .. })
        ));
    }
    Ok(())
}

#[test]
fn an_inexact_or_misplaced_marker_keeps_the_response_path() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let binding = LogoutBinding::Post;
    let xml = logout_request_xml("_extension", SP_ENTITY_ID, Some(IDP_SLO_POST));
    let marker = format!(r#"<Asynchronous xmlns="{ASYNC_NAMESPACE}"/>"#);
    let protocol_extensions = |child: &str| format!("<samlp:Extensions>{child}</samlp:Extensions>");
    for extension in [
        protocol_extensions(r#"<Asynchronous xmlns="urn:example:unrelated"/>"#),
        protocol_extensions(&format!(
            r#"<wrapper xmlns="urn:example:unrelated">{marker}</wrapper>"#
        )),
        protocol_extensions(&format!(
            r#"<Asynchronous xmlns="{ASYNC_NAMESPACE}" value="true"/>"#
        )),
        protocol_extensions(&format!(
            r#"<Asynchronous xmlns="{ASYNC_NAMESPACE}">true</Asynchronous>"#
        )),
        protocol_extensions(&format!(
            r#"<Asynchronous xmlns="{ASYNC_NAMESPACE}"><child/></Asynchronous>"#
        )),
        format!(
            r#"<other:Extensions xmlns:other="urn:example:unrelated">{marker}</other:Extensions>"#
        ),
        marker,
    ] {
        let xml = xml.replacen("<saml:NameID>", &format!("{extension}<saml:NameID>"), 1);
        let action = idp.receive_slo_with_async(
            &sp_descriptor,
            signed_logout_request_input(&xml, binding)?,
            validation(),
        )?;
        assert!(matches!(action, IdpLogoutAction::Respond(_)), "{extension}");
    }
    Ok(())
}

#[test]
fn a_marker_with_schema_instance_hints_selects_local_completion(
) -> Result<(), Box<dyn std::error::Error>> {
    const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
    let (sp, idp) = facades()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let binding = LogoutBinding::Post;
    let xml = logout_request_xml("_hinted", SP_ENTITY_ID, Some(IDP_SLO_POST));
    let marker = |attributes: &str| {
        format!(
            r#"<samlp:Extensions><aslo:Asynchronous xmlns:aslo="{ASYNC_NAMESPACE}" xmlns:xsi="{XSI}" {attributes}/></samlp:Extensions>"#
        )
    };
    let receive = |attributes: &str| -> Result<_, Box<dyn std::error::Error>> {
        let xml = xml.replacen(
            "<saml:NameID>",
            &format!("{}<saml:NameID>", marker(attributes)),
            1,
        );
        Ok(idp.receive_slo_with_async(
            &sp_descriptor,
            signed_logout_request_input(&xml, binding)?,
            validation(),
        )?)
    };
    for attributes in [
        r#"xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo saml-async-slo-v1.0.xsd""#,
        r#"xsi:noNamespaceSchemaLocation="extension.xsd""#,
        r#"xsi:type="aslo:AsynchronousType""#,
    ] {
        assert!(
            matches!(receive(attributes)?, IdpLogoutAction::CompleteLocally(_)),
            "{attributes}"
        );
    }
    for attributes in [
        r#"xsi:nil="true""#,
        r#"xsi:other="value""#,
        r#"xmlns:other="urn:example:unrelated" other:schemaLocation="extension.xsd""#,
    ] {
        assert!(
            matches!(receive(attributes)?, IdpLogoutAction::Respond(_)),
            "{attributes}"
        );
    }
    Ok(())
}

#[test]
fn async_slo_requires_authentication_and_refuses_newer_versions_locally(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    for binding in UNSIGNED_BINDINGS {
        let ordinary = logout_request_xml(
            "_asynchronous",
            SP_ENTITY_ID,
            Some(LocalSloRole::Idp.endpoint(binding)),
        )
        .replacen(r#"Version="2.0""#, r#"Version="2.1""#, 1);
        let asynchronous = ordinary.replacen(
            "<saml:NameID>",
            &format!(
                r#"<samlp:Extensions><flag:Asynchronous xmlns:flag="{ASYNC_NAMESPACE}"/></samlp:Extensions><saml:NameID>"#
            ),
            1,
        );
        let receive = |input| idp.receive_slo_with_async(&sp_descriptor, input, validation());
        assert!(matches!(
            receive(unsigned_logout_request_input(&asynchronous, binding)?),
            Err(SamlError::SignatureMissing)
        ));
        let result = receive(signed_logout_request_input(&asynchronous, binding)?);
        assert!(
            matches!(result, Err(SamlError::ProtocolProfile(_))),
            "{result:?}"
        );
        assert!(matches!(
            receive(signed_logout_request_input(&ordinary, binding)?),
            Err(SamlError::LogoutRequestRefused { .. })
        ));
        assert!(matches!(
            idp.receive_slo(
                &sp_descriptor,
                signed_logout_request_input(&asynchronous, binding)?,
                validation(),
            ),
            Err(SamlError::LogoutRequestRefused { .. })
        ));
    }
    Ok(())
}

#[test]
fn async_slo_keeps_soap_and_simple_sign_on_the_ordinary_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for binding in [LogoutBinding::Soap, LogoutBinding::SimpleSign] {
        let result =
            sp.start_async_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding));
        assert!(matches!(
            result,
            Err(SamlError::UnsupportedBinding { binding: actual, .. }) if actual == binding.into()
        ));

        let xml = logout_request_xml(
            "_ordinary_binding",
            SP_ENTITY_ID,
            Some(LocalSloRole::Idp.endpoint(binding)),
        )
        .replacen(
            "<saml:NameID>",
            &format!(
                r#"<samlp:Extensions><Asynchronous xmlns="{ASYNC_NAMESPACE}"/></samlp:Extensions><saml:NameID>"#
            ),
            1,
        );
        let action = idp.receive_slo_with_async(
            &sp_descriptor,
            signed_logout_request_input(&xml, binding)?,
            validation(),
        )?;
        assert!(matches!(action, IdpLogoutAction::Respond(_)), "{binding:?}");
    }
    Ok(())
}
