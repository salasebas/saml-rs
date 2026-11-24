use super::*;
use saml_rs::constants::namespace;
use saml_rs::{
    ArtifactDelivery, Attribute, AttributeValue, Attributes, CertificatePem, Credentials, NameId,
    PrivateKeyPem, ResourceLimit, RespondSso, SsoAssertion, X509Credential,
};

#[test]
fn signed_sso_artifact_must_fit_before_the_store_is_written() -> TestResult {
    let credential = X509Credential::new(
        CertificatePem::new(include_str!(
            "../../fixtures/key/sp/cert.unencrypted.pkcs8.cer"
        )),
        PrivateKeyPem::new(include_str!(
            "../../fixtures/key/sp/privkey.unencrypted.pkcs8.pem"
        )),
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .credentials(Credentials::default().with_signing_credential(credential))
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new(RESOLUTION_URL)?,
        ))
        .build()?,
    );
    let peer = |endpoint| -> Result<SpDescriptor, SamlError> {
        let entity = EntityId::try_new(SP_ENTITY_ID)?;
        let sp = ServiceProvider::new(SpConfig::builder(entity.clone(), endpoint).build()?);
        SpDescriptor::from_metadata_xml(entity, sp.metadata_xml(), MetadataTrustPolicy::Unverified)
    };
    let acs = "https://sp.example.com/acs";
    let post_peer = peer(AcsEndpoint::post(acs)?)?;
    let artifact_peer = peer(AcsEndpoint::artifact(acs)?)?;
    let assertion = |attribute_bytes| {
        SsoAssertion::new(NameId::new("alice@example.com")).attributes(Attributes::new([
            Attribute::new(
                "entitlements",
                [AttributeValue::new("a".repeat(attribute_bytes))],
            ),
        ]))
    };
    let posted_xml = |attribute_bytes| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let response =
            idp.initiate_sso(&post_peer, assertion(attribute_bytes), RespondSso::post())?;
        let encoded = response
            .post_form()?
            .value("SAMLResponse")
            .ok_or("no SAMLResponse")?;
        Ok(STANDARD.decode(encoded)?)
    };
    let limits = XmlLimits::default();
    let request_id = "_".repeat(limits.max_attribute_value_bytes);
    let overhead = super::super::budget::response_envelope_overhead(&request_id);
    let signed_response_overhead = posted_xml(1)?.len() - 1;
    let oversized_envelope = limits.max_bytes + 1;
    let attribute_bytes = oversized_envelope
        .checked_sub(overhead + signed_response_overhead)
        .ok_or("budget cannot hold a small signed response")?;
    let signed = posted_xml(attribute_bytes)?;
    let xml = roxmltree::Document::parse(std::str::from_utf8(&signed)?)?;
    let signature = xml
        .descendants()
        .find(|node| node.has_tag_name((namespace::DSIG, "Signature")))
        .ok_or("Response has no XML signature")?;
    assert_eq!(signed.len() + overhead, oversized_envelope);
    assert!(signed.len() + overhead - signature.range().len() <= limits.max_bytes);

    let mut issued = SharedExternalStore::new(ARTIFACT_LIFETIME);
    let outcome = idp.initiate_sso_artifact(
        &artifact_peer,
        assertion(attribute_bytes),
        RespondSso::artifact(ArtifactDelivery::post_form(0)),
        &mut issued,
    );
    assert!(
        matches!(outcome, Err(SamlError::LimitExceeded {
        limit: ResourceLimit::XmlBytes, maximum, ..
    }) if maximum == limits.max_bytes),
        "expected the signed envelope to exceed the budget, got {outcome:?}"
    );
    assert!(issued
        .rows
        .lock()
        .map_err(|_| "store lock poisoned")?
        .is_empty());
    Ok(())
}
