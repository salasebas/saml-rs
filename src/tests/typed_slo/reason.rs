use super::*;

const REASON: &str = "https://example.com/logout?initiator=admin&scope=all";
const USER_REASON: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";

#[test]
fn typed_slo_writes_reason_in_signed_requests_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for binding in LOGOUT_BINDINGS_WITH_SOAP {
        let options = start_slo_for_binding(binding)?;
        let from_sp = sp.start_slo(
            &idp_descriptor,
            subject()?,
            options.clone().reason(USER_REASON),
        )?;
        let from_idp = idp.start_slo(&sp_descriptor, subject()?, options.reason(REASON))?;
        for (outbound, expected) in [
            (&from_sp.outbound, USER_REASON),
            (&from_idp.outbound, REASON),
        ] {
            let xml = outbound_xml(outbound, "SAMLRequest")?;
            let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
            assert_eq!(document.root.attr("Reason"), Some(expected), "{binding:?}");
        }
        idp.receive_slo(
            &sp_descriptor,
            logout_request_input(&from_sp.outbound, binding)?,
            validation(),
        )?;
        sp.receive_slo(
            &idp_descriptor,
            logout_request_input(&from_idp.outbound, binding)?,
            validation(),
        )?;
    }
    Ok(())
}

#[test]
fn typed_slo_rejects_invalid_reason_uris() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for reason in ["logout/admin", " \t\n", "urn:example:bad%zz"] {
        let options = StartSlo::redirect().reason(reason);
        for result in [
            sp.start_slo(&idp_descriptor, subject()?, options.clone()),
            idp.start_slo(&sp_descriptor, subject()?, options),
        ] {
            assert!(matches!(result, Err(SamlError::Invalid(_))), "{result:?}");
        }
    }
    Ok(())
}

#[test]
fn typed_slo_omits_reason_by_default_and_collapses_supplied_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    for (options, expected) in [
        (StartSlo::post(), None),
        (
            StartSlo::post().reason(format!(" \t{REASON}\n")),
            Some(REASON),
        ),
    ] {
        let started = sp.start_slo(&idp_descriptor, subject()?, options)?;
        let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
        let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
        assert_eq!(document.root.attr("Reason"), expected);
    }
    Ok(())
}
