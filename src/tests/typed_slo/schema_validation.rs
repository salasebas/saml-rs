use super::*;

#[test]
fn schema_policy_covers_both_logout_soap_directions() -> Result<(), Box<dyn std::error::Error>> {
    fn reject_envelope(xml: &str) -> Result<(), String> {
        let document = roxmltree::Document::parse(xml).map_err(|error| error.to_string())?;
        if document.root_element().tag_name().name() == "Envelope" {
            return Err("schema rejected logout envelope".into());
        }
        Ok(())
    }
    let xml = saml_rs::XmlPolicy {
        schema_validator: Some(reject_envelope),
        ..saml_rs::XmlPolicy::default()
    };
    let sp = Saml::sp(
        sp_config_builder(signing_sp_validation(), None)?
            .xml(xml)
            .build()?,
    )?;
    let rejecting_idp = Saml::idp(
        idp_config_builder(signed_authn_request_idp_validation(), None)?
            .xml(xml)
            .build()?,
    )?;
    let accepting_idp = Saml::idp(idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &accepting_idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::soap())?;
    let envelope = started.outbound.soap_request()?.envelope();
    let result = rejecting_idp.receive_slo(
        &sp_descriptor,
        Inbound::soap(envelope, SoapChannel::unattested()),
        validation(),
    );
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected logout envelope"),
        "expected rejection of the request envelope, got {result:?}"
    );
    let received = accepting_idp.receive_slo(
        &sp_descriptor,
        Inbound::soap(envelope, SoapChannel::unattested()),
        validation(),
    )?;
    let response = accepting_idp.respond_slo(&sp_descriptor, &received, RespondSlo::soap())?;
    let result = sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        Inbound::soap(
            response.soap_response()?.envelope(),
            SoapChannel::unattested(),
        ),
        validation(),
    );
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected logout envelope"),
        "expected rejection of the response envelope, got {result:?}"
    );
    Ok(())
}

#[test]
fn schema_policy_covers_both_logout_post_directions() -> Result<(), Box<dyn std::error::Error>> {
    fn reject_logout(xml: &str) -> Result<(), String> {
        let document = roxmltree::Document::parse(xml).map_err(|error| error.to_string())?;
        if matches!(
            document.root_element().tag_name().name(),
            "LogoutRequest" | "LogoutResponse"
        ) {
            return Err("schema rejected logout document".into());
        }
        Ok(())
    }
    let xml = saml_rs::XmlPolicy {
        schema_validator: Some(reject_logout),
        ..saml_rs::XmlPolicy::default()
    };
    let (sp, idp) = facades()?;
    let rejecting_idp = Saml::idp(
        idp_config_builder(signed_authn_request_idp_validation(), None)?
            .xml(xml)
            .build()?,
    )?;
    let rejecting_sp = Saml::sp(
        sp_config_builder(signing_sp_validation(), None)?
            .xml(xml)
            .build()?,
    )?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let fields = post_fields(&started.outbound)?;
    let result =
        rejecting_idp.receive_slo(&sp_descriptor, Inbound::post(fields.clone()), validation());
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected logout document"),
        "expected rejection of the request document, got {result:?}"
    );
    let received = idp.receive_slo(&sp_descriptor, Inbound::post(fields), validation())?;
    let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    let fields = post_fields(&response)?;
    let result = rejecting_sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        Inbound::post(fields.clone()),
        validation(),
    );
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == "schema rejected logout document"),
        "expected rejection of the response document, got {result:?}"
    );
    sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        Inbound::post(fields),
        validation(),
    )?;
    Ok(())
}
