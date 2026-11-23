use super::*;

#[test]
fn receive_slo_requires_one_direct_principal_identifier_before_replay() {
    let role = LocalSloRole::Idp;
    let binding = LogoutBinding::Post;
    let xml = logout_request_xml(
        "_logout",
        sender_entity_id(role),
        Some(role.endpoint(binding)),
    );
    let name_id = "<saml:NameID>alice@example.com</saml:NameID>";
    for (case, identifiers) in [
        ("missing", String::new()),
        (
            "nested",
            format!(
                r#"<samlp:Extensions><other:Context xmlns:other="urn:example:extension">{name_id}</other:Context></samlp:Extensions>"#
            ),
        ),
        (
            "foreign namespace",
            r#"<other:BaseID xmlns:other="urn:example:extension"/>"#.into(),
        ),
        ("repeated", name_id.repeat(2)),
        (
            "mixed plaintext",
            format!(
                r#"{name_id}<saml:BaseID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:other="urn:example:extension" xsi:type="other:AccountId">opaque</saml:BaseID>"#
            ),
        ),
    ] {
        let mut cache = RecordingReplayCache::default();
        let result = receive_crafted_logout_request(
            &xml.replace(name_id, &identifiers),
            binding,
            role,
            RequestProtection::Signed,
            validation_with_cache(&mut cache),
        );
        assert!(
            matches!(result, Err(SamlError::ProtocolProfile(_))),
            "{case}: expected ProtocolProfile, got {:?}",
            result.err()
        );
        assert!(cache.seen.is_empty(), "{case}: stored the invalid request");
    }
}

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
    let sp = ServiceProvider::new(
        sp_config_builder(signing_sp_validation())?
            .xml(xml)
            .build()?,
    );
    let rejecting_idp = IdentityProvider::new(
        idp_config_builder(signed_authn_request_idp_validation())?
            .xml(xml)
            .build()?,
    );
    let accepting_idp = IdentityProvider::new(idp_config()?);
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
    let response = accepting_idp.respond_slo(
        &sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::soap(),
    )?;
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
    let rejecting_idp = IdentityProvider::new(
        idp_config_builder(signed_authn_request_idp_validation())?
            .xml(xml)
            .build()?,
    );
    let rejecting_sp = ServiceProvider::new(
        sp_config_builder(signing_sp_validation())?
            .xml(xml)
            .build()?,
    );
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
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
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
