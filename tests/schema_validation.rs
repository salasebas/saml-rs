use std::time::SystemTime;

use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, EntityId, FormField, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, MetadataTrustPolicy, PaosAuthnRequest, ReplayPolicy, Saml, SamlError,
    SamlValidationContext, SchemaValidator, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, StartSso, XmlPolicy,
};

const SP: &str = "https://sp.example.com/metadata";
const IDP: &str = "https://idp.example.com/metadata";
const SOAP: &str = "https://idp.example.com/sso";
const REJECTED: &str = "schema rejected peer XML";

fn reject_xml(_: &str) -> Result<(), String> {
    Err(REJECTED.into())
}

fn reject_envelope(xml: &str) -> Result<(), String> {
    let document = roxmltree::Document::parse(xml).map_err(|error| error.to_string())?;
    if document.root_element().tag_name().name() == "Envelope" {
        reject_xml(xml)?;
    }
    Ok(())
}

fn policy(validator: Option<SchemaValidator>) -> XmlPolicy {
    XmlPolicy {
        schema_validator: validator,
        ..XmlPolicy::default()
    }
}

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP)?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )
}

fn idp(validator: Option<SchemaValidator>) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP)?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
            .validation(IdpValidationPolicy::compatibility())
            .xml(policy(validator))
            .build()?,
    )
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn assert_rejected<T: std::fmt::Debug>(result: Result<T, SamlError>) {
    assert!(
        matches!(result, Err(SamlError::Invalid(ref reason)) if reason == REJECTED),
        "expected schema rejection, got {result:?}"
    );
}

#[test]
fn configured_schema_validator_rejects_typed_peer_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp(Some(reject_xml))?;
    assert_rejected(IdpDescriptor::from_metadata_xml_with_policy(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
        &policy(Some(reject_xml)),
    ));
    assert_rejected(SpDescriptor::from_metadata_xml_with_policy(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
        &policy(Some(reject_xml)),
    ));
    IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok(())
}

#[test]
fn typed_schema_policy_is_isolated_and_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let rejecting = idp(Some(reject_xml))?;
    let accepting = idp(None)?;
    let peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let destination = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        accepting.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let started = sp.start_sso(&destination, StartSso::post())?;
    let fields: Vec<FormField> = started.outbound.post_form()?.fields().to_vec();
    assert_rejected(rejecting.receive_sso(
        &peer,
        BrowserInput::<AuthnRequest>::post(fields.clone()),
        validation(),
    ));
    accepting.receive_sso(
        &peer,
        BrowserInput::<AuthnRequest>::post(fields.clone()),
        validation(),
    )?;
    assert_rejected(rejecting.receive_sso(
        &peer,
        BrowserInput::<AuthnRequest>::post(fields),
        validation(),
    ));
    Ok(())
}

#[test]
fn schema_policy_covers_paos_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp(Some(reject_envelope))?;
    let peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let destination = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    use base64::Engine;
    let started = sp.start_sso(&destination, StartSso::post())?;
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&started.outbound.raw_context().context)?,
    )?;
    let envelope = format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>{xml}</soap:Body></soap:Envelope>"#
    );
    let request = PaosAuthnRequest::from_envelope(envelope, SOAP)?;
    assert_rejected(idp.receive_paos_sso(&peer, &request, validation()));
    self::idp(None)?.receive_paos_sso(&peer, &request, validation())?;
    Ok(())
}
