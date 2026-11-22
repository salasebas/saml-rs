use super::*;
use saml_rs::{ResourceLimit, MAX_RECEIVED_RELAY_STATE_BYTES};

#[test]
fn forwarded_request_keeps_its_relay_state_limit() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let endpoint = EndpointUrl::try_new(IDP_SOAP)?;
    let started = sp.start_paos_sso(&idp_descriptor, StartPaosSso::new(endpoint.clone()))?;
    let (_, request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let document = Document::parse(&request)?;
    let authn = body_element(&request, document.root_element(), "AuthnRequest")?;
    let state = "r".repeat(81);
    let header = format!(
        r#"<ecp:RelayState xmlns:ecp="{ECP_PROFILE}" SOAP-ENV:mustUnderstand="0" SOAP-ENV:actor="http://schemas.xmlsoap.org/soap/actor/next">{state}</ecp:RelayState>"#
    );
    let forwarded = soap_envelope(&header, &authn);
    assert!(matches!(
        idp.receive_paos_sso(&sp_descriptor, &forwarded, &endpoint, validation()),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn responder_added_state_uses_the_receive_limit() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (_, idp_request) = enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let document = Document::parse(answered.envelope())?;
    let response = body_element(answered.envelope(), document.root_element(), "Response")?;
    let finish = |state: &str| {
        let envelope = soap_envelope(&relay_state_header(state), &response);
        sp.finish_paos_sso(&idp_descriptor, &started.pending, &envelope, validation())
    };
    let mut state = "é".repeat(2048);
    let session = finish(&state)?;
    assert_eq!(
        session.relay_state().map(RelayState::as_str),
        Some(state.as_str())
    );
    state.push('x');
    assert!(matches!(
        finish(&state),
        Err(SamlError::LimitExceeded {
            limit: ResourceLimit::RelayStateBytes,
            maximum: MAX_RECEIVED_RELAY_STATE_BYTES,
            ..
        })
    ));
    Ok(())
}
