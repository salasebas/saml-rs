use super::*;
use saml_rs::constants::status_code::{REQUEST_VERSION_TOO_HIGH, VERSION_MISMATCH};

#[test]
fn authenticated_newer_logout_requests_get_a_signed_version_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for (role, version, subordinate) in [
        (LocalSloRole::Sp, "2.1", None),
        (LocalSloRole::Idp, "3.0", Some(REQUEST_VERSION_TOO_HIGH)),
    ] {
        let binding = LogoutBinding::Soap;
        let xml = logout_request_xml(
            "_newer_version",
            sender_entity_id(role),
            Some(role.endpoint(binding)?),
        )
        .replace(r#"Version="2.0""#, &format!(r#"Version="{version}""#));
        let receive = |input| match role {
            LocalSloRole::Sp => sp.receive_slo(&idp_descriptor, input, validation()),
            LocalSloRole::Idp => idp.receive_slo(&sp_descriptor, input, validation()),
        };
        assert!(matches!(
            receive(unsigned_logout_request_input(&xml, binding)?),
            Err(SamlError::SignatureMissing)
        ));
        let Err(SamlError::LogoutRequestRefused { refusal, .. }) =
            receive(signed_logout_request_input(&xml, binding)?)
        else {
            return Err("the signed version mismatch must carry a refusal".into());
        };
        let response = match role {
            LocalSloRole::Sp => {
                sp.respond_slo_refusal(&idp_descriptor, &refusal, RespondSlo::soap())?
            }
            LocalSloRole::Idp => {
                idp.respond_slo_refusal(&sp_descriptor, &refusal, RespondSlo::soap())?
            }
        };
        let xml = soap_body_xml(response.soap_response()?.envelope())?;
        assert!(root_has_signature(&xml)?);
        let document = roxmltree::Document::parse(&xml)?;
        let root = document.root_element();
        assert_eq!(root.attribute("Version"), Some("2.0"));
        assert_eq!(root.attribute("InResponseTo"), Some("_newer_version"));
        let codes: Vec<_> = root
            .descendants()
            .filter(|node| node.has_tag_name("StatusCode"))
            .filter_map(|node| node.attribute("Value"))
            .collect();
        assert_eq!(
            codes,
            [Some(VERSION_MISMATCH), subordinate]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}
