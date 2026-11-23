use super::*;
use saml_rs::constants::status_code::{REQUEST_VERSION_TOO_HIGH, VERSION_MISMATCH};

#[test]
fn the_sp_refuses_a_signed_newer_minor_logout_request_over_soap(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let binding = LogoutBinding::Soap;
    let xml = logout_request_xml("_newer_version", IDP_ENTITY_ID, Some(SP_SLO_SOAP))
        .replace(r#"Version="2.0""#, r#"Version="2.1""#);
    let receive = |input| sp.receive_slo(&idp_descriptor, input, validation());
    assert!(matches!(
        receive(unsigned_logout_request_input(&xml, binding)?),
        Err(SamlError::SignatureMissing)
    ));
    let legacy = xml.replace(r#"Version="2.1""#, r#"Version="1.1""#);
    assert!(matches!(
        receive(signed_logout_request_input(&legacy, binding)?),
        Err(SamlError::ProtocolProfile(_))
    ));
    let Err(SamlError::LogoutRequestRefused { refusal, .. }) =
        receive(signed_logout_request_input(&xml, binding)?)
    else {
        return Err("the signed version mismatch must carry a refusal".into());
    };
    let response = sp.respond_slo_refusal(&idp_descriptor, &refusal, RespondSlo::soap())?;
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
    assert_eq!(codes, [VERSION_MISMATCH]);
    Ok(())
}

#[test]
fn a_browser_refusal_uses_the_receive_channel_and_keeps_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(idp_config_with_logout_response_template(
        saml_rs::config::LOGOUT_RESPONSE_TEMPLATE.to_string(),
    )?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("logout-return")?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state.clone()),
    )?;
    let xml = logout_request_xml(
        started.pending.request_id().as_str(),
        SP_ENTITY_ID,
        Some(IDP_SLO_POST),
    )
    .replace(r#"Version="2.0""#, r#"Version="3.0""#);
    let key = read_private_key(PRIVKEY, None)?;
    let signed = sign_saml_xml(&xml, true, &key, CERT, RSA_SHA256, &[], None)?;
    let inbound = Inbound::post(vec![
        FormField::new("SAMLRequest", STANDARD.encode(signed.as_bytes())),
        FormField::new("RelayState", relay_state.as_str()),
    ]);
    let Err(SamlError::LogoutRequestRefused { refusal, .. }) =
        idp.receive_slo(&sp_descriptor, inbound, validation())
    else {
        return Err("the signed version mismatch must carry a refusal".into());
    };
    assert!(matches!(
        idp.respond_slo_refusal(&sp_descriptor, &refusal, RespondSlo::soap()),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Soap
        })
    ));
    let response = idp.respond_slo_refusal(&sp_descriptor, &refusal, RespondSlo::post())?;
    assert_eq!(response.relay_state(), Some(&relay_state));
    let result = sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        logout_response_input(&response, LogoutBinding::Post)?,
        validation(),
    );
    let Err(SamlError::StatusNotSuccess { status, .. }) = result else {
        return Err(format!("expected a correlated SAML error response, got {result:?}").into());
    };
    assert_eq!(
        status,
        Status::version_mismatch()
            .with_subordinate(SubordinateStatusCode::try_new(REQUEST_VERSION_TOO_HIGH)?)
    );
    Ok(())
}
