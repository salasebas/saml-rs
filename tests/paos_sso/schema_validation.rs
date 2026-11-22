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
    let mut xml = saml_rs::XmlPolicy::default();
    xml.schema_validator = Some(reject_envelope);
    let rejecting = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(credentials())
        .validation(SpValidationPolicy::default())
        .xml(xml)
        .build()?,
    );
    let started = sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let (client, idp_request) =
        enhanced_client_takes_authn_request(started.http_response.envelope())?;
    let received = idp.receive_paos_sso(
        &sp_descriptor,
        &idp_request,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    let answered =
        idp.respond_paos_sso(&sp_descriptor, &received, SsoAssertion::new(principal()))?;
    let response = enhanced_client_takes_response(&client, answered.envelope())?;
    let result =
        rejecting.finish_paos_sso(&idp_descriptor, &started.pending, &response, validation());
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected PAOS response envelope"),
        "expected rejection of the SP envelope, got {result:?}"
    );
    sp.finish_paos_sso(&idp_descriptor, &started.pending, &response, validation())?;
    Ok(())
}
