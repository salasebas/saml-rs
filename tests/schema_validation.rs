#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

use policies_without_crypto::sp_validation_without_crypto;

use std::time::SystemTime;

use saml_rs::{
    AcsEndpoint, EntityId, FormField, IdentityProvider, IdpConfig, IdpDescriptor, Inbound,
    MetadataTrustPolicy, ReplayPolicy, SamlError, SamlValidationContext, SchemaValidator,
    ServiceProvider, SpConfig, SpDescriptor, SsoEndpoint, StartSso, XmlPolicy,
};

const SP: &str = "https://sp.example.com/metadata";
const IDP: &str = "https://idp.example.com/metadata";
const REJECTED: &str = "schema rejected peer XML";

fn reject_xml(_: &str) -> Result<(), String> {
    Err(REJECTED.into())
}

fn policy(validator: Option<SchemaValidator>) -> XmlPolicy {
    let mut policy = XmlPolicy::default();
    policy.schema_validator = validator;
    policy
}

fn sp() -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP)?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .build()?,
    ))
}

fn idp(validator: Option<SchemaValidator>) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP)?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .xml(policy(validator))
        .build()?,
    ))
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
    assert_rejected(rejecting.receive_sso(&peer, Inbound::post(fields.clone()), validation()));
    accepting.receive_sso(&peer, Inbound::post(fields.clone()), validation())?;
    assert_rejected(rejecting.receive_sso(&peer, Inbound::post(fields), validation()));
    Ok(())
}

#[test]
fn schema_callback_participates_in_xml_policy_equality() {
    let validator: SchemaValidator = reject_xml;
    let unchecked = policy(None);
    let checked = policy(Some(validator));
    assert_ne!(unchecked, checked);
    assert_ne!(checked, unchecked);
    let copied = checked;
    assert_eq!(checked, copied);

    let mut different_limits = checked;
    different_limits.limits.max_bytes = 128;
    assert_ne!(checked, different_limits);
}
