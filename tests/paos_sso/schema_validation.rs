use super::*;

#[test]
fn schema_policy_covers_the_sp_paos_envelope() -> Result<(), Box<dyn std::error::Error>> {
    fn reject_envelope(xml: &str) -> Result<(), String> {
        let document = Document::parse(xml).map_err(|error| error.to_string())?;
        if document.root_element().tag_name().name() == "Envelope" {
            return Err("schema rejected PAOS response envelope".into());
        }
        Ok(())
    }
    let (sp, idp, sp_descriptor, idp_descriptor) = parties()?;
    let rejecting = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.with_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .xml(saml_rs::XmlPolicy {
                schema_validator: Some(reject_envelope),
                ..saml_rs::XmlPolicy::default()
            })
            .build()?,
    )?;
    let started = sp.start_paos_sso(
        &idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_SOAP)?,
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &PaosAuthnRequest::from_envelope(idp_request, IDP_SOAP)?,
        validation(),
    )?;
    let answered = idp.respond_paos_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let envelope = enhanced_client_takes_response(&client, answered.envelope())?;
    let response = PaosSsoResponse::from_envelope(envelope)?;
    let result =
        rejecting.finish_paos_sso(&idp_descriptor, &started.pending, &response, validation());
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected PAOS response envelope"),
        "expected rejection of the SP envelope, got {result:?}"
    );
    sp.finish_paos_sso(&idp_descriptor, &started.pending, &response, validation())?;
    Ok(())
}
