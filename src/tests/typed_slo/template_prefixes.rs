use super::*;
use saml_rs::config::{LOGOUT_REQUEST_TEMPLATE, LOGOUT_RESPONSE_TEMPLATE};

#[test]
fn custom_logout_templates_preserve_extension_literals_when_prefixes_are_swapped(
) -> Result<(), Box<dyn std::error::Error>> {
    const NOTE: &str = concat!(
        r#"<ext:Note xmlns:ext="urn:example:logout" label="xmlns:saml=example">"#,
        "expected xmlns:samlp=protocol",
        "<![CDATA[<saml:Issuer/>]]><!-- </samlp:LogoutRequest> -->",
        "</ext:Note>",
    );
    let with_extension = |template: &str| {
        template.replace(
            "</saml:Issuer>",
            &format!("</saml:Issuer><samlp:Extensions>{NOTE}</samlp:Extensions>"),
        )
    };
    let templates = TemplatePolicy {
        tag_prefix_protocol: "saml".into(),
        tag_prefix_assertion: "samlp".into(),
        logout_request_template: Some(with_extension(LOGOUT_REQUEST_TEMPLATE)),
        logout_response_template: Some(with_extension(LOGOUT_RESPONSE_TEMPLATE)),
        ..TemplatePolicy::default()
    };
    let sp = ServiceProvider::new(
        sp_config_builder(signing_sp_validation(), None)?
            .templates(templates.clone())
            .build()?,
    );
    let idp = IdentityProvider::new(
        idp_config_builder(signed_authn_request_idp_validation(), None)?
            .templates(templates)
            .build()?,
    );
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect())?;
    let request = logout_request_input(&started.outbound, LogoutBinding::Redirect)?;
    let received = idp.receive_slo(&sp_descriptor, request, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::redirect(),
    )?;

    for (xml, root, issuer) in [
        (
            outbound_xml(&started.outbound, "SAMLRequest")?,
            "LogoutRequest",
            SP_ENTITY_ID,
        ),
        (
            outbound_xml(&response, "SAMLResponse")?,
            "LogoutResponse",
            IDP_ENTITY_ID,
        ),
    ] {
        assert!(xml.contains(&format!("<saml:{root} ")));
        assert!(xml.contains(r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:protocol""#));
        assert!(xml.contains(r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:assertion""#));
        assert!(xml.contains(&format!("<samlp:Issuer>{issuer}</samlp:Issuer>")));
        assert!(xml.contains(NOTE), "{root}: {xml}");
    }
    Ok(())
}
