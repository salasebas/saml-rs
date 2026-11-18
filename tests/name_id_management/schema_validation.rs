use super::*;

#[test]
fn schema_policy_covers_both_name_id_management_soap_directions() -> TestResult {
    fn reject(_: &str) -> Result<(), String> {
        Err("schema rejected management envelope".into())
    }
    let idp = Saml::idp(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            IDP_NIM_URL,
        )?))
        .validation(saml_rs::IdpValidationPolicy::compatibility())
        .xml(saml_rs::XmlPolicy {
            schema_validator: Some(reject),
            ..saml_rs::XmlPolicy::default()
        })
        .build()?,
    )?;
    let sp = soap_service_provider()?;
    let envelope = sp_request(&format!(
        "{}<samlp:NewID>sp-alias</samlp:NewID>",
        current_name_id_xml()
    ))?;
    let result = idp.receive_name_id_management(&sp, &envelope, authenticated(), validation());
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected management envelope"),
        "expected rejection of the request, got {result:?}"
    );
    let started = idp.start_name_id_management(
        &sp,
        &NameId::new("current-value", None),
        &NameIdChange::NewId("new-value".into()),
        IdentifierEncryptionPolicy::PlaintextIdentifiers,
        authenticated(),
    )?;
    let xml = body(started.request().envelope())?;
    let request_id = attribute(&xml, "ID").ok_or("missing request ID")?;
    let response = sp_response(request_id, SP_ENTITY_ID, &success_status())?;
    let result = started.finish(&response);
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected management envelope"),
        "expected rejection of the response, got {result:?}"
    );
    Ok(())
}
