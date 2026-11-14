use super::*;

#[test]
fn exactly_requested_authn_context_is_checked_and_written() -> Result<(), Box<dyn std::error::Error>>
{
    const SMARTCARD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?.allow_unsigned_authn_request(),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let requested = idp_request.replace(
        "</samlp:AuthnRequest>",
        &format!("<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"),
    );
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(requested, IDP_SOAP)?,
        validation(),
    )?;
    let unspecified = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    );
    assert!(matches!(unspecified, Err(SamlError::Invalid(_))));

    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default().authn_context(AuthnContextReference::class(SMARTCARD)?),
    )?;
    assert!(answered.envelope().contains(&format!(
        "<saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef>"
    )));
    let request = enhanced_client_takes_response(&client, answered.envelope())?;
    let session = sp.finish_paos_sso(
        &idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(request)?,
        validation(),
    )?;
    assert_eq!(
        session
            .authn_session()
            .authn_context()
            .and_then(|context| context.class_reference())
            .map(AuthnContextReference::uri),
        Some(SMARTCARD),
    );
    Ok(())
}
