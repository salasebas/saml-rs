use super::*;
use saml_rs::{SignatureAction, SignatureConfig, TemplatePolicy};

#[test]
fn typed_logout_round_trips_with_swapped_prefixes() -> Result<(), Box<dyn std::error::Error>> {
    let templates = TemplatePolicy {
        tag_prefix_protocol: "saml".into(),
        tag_prefix_assertion: "samlp".into(),
        signature_config: Some(SignatureConfig {
            prefix: "sig".into(),
            reference: None,
            action: SignatureAction::After,
        }),
        ..TemplatePolicy::default()
    };
    let sp = ServiceProvider::new(
        sp_config_builder(signing_sp_validation())?
            .templates(templates.clone())
            .build()?,
    );
    let idp = IdentityProvider::new(
        idp_config_builder(signed_authn_request_idp_validation())?
            .templates(templates)
            .build()?,
    );
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request = logout_request_input(&started.outbound, LogoutBinding::Post)?;
    let received = idp.receive_slo(&sp_descriptor, request, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post(),
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
        let document = roxmltree::Document::parse(&xml)?;
        let mut children = document
            .root_element()
            .children()
            .filter(|node| node.is_element());
        assert_eq!(
            children.next().map(|node| node.tag_name().name()),
            Some("Issuer")
        );
        let signature = children.next().ok_or("missing signature")?;
        assert_eq!(signature.tag_name().name(), "Signature");
        assert_eq!(
            signature.lookup_namespace_uri(Some("sig")),
            Some(saml_rs::constants::namespace::DSIG),
        );
    }
    let completed = sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        logout_response_input(&response, LogoutBinding::Post)?,
        validation(),
    )?;
    assert_eq!(completed.response().status(), &Status::success());
    Ok(())
}
