//! `Destination` on an AuthnRequest that the identity provider receives over
//! SOAP in Enhanced Client/Proxy SSO.
#![cfg(crypto)]

use super::common::signing_credentials;

use std::time::SystemTime;

use roxmltree::Document;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::{
    AcsEndpoint, AuthnRequestValidationPolicy, EndpointUrl, EntityId, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, ReplayPolicy, SamlValidationContext,
    ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartPaosSso,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const IDP_SOAP: &str = "https://idp.example.com/sso/soap";
const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn signed_paos_authn_request_without_destination_is_accepted_under_every_signing_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.com/acs/post")?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(SpValidationPolicy::default())
        .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    for (policy, validation) in [
        ("recommended", IdpValidationPolicy::default()),
        (
            "RequireSigned",
            IdpValidationPolicy {
                authn_requests: AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::default()
            },
        ),
    ] {
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post("https://idp.example.com/sso/post")?,
            )
            .credentials(signing_credentials())
            .validation(validation)
            .build()?,
        );
        let idp_descriptor = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let started = sp.start_paos_sso(
            &idp_descriptor,
            StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
        )?;
        let envelope = resigned_without_destination(started.http_response.envelope())?;
        let received = idp
            .receive_paos_sso(
                &sp_descriptor,
                &envelope,
                &EndpointUrl::try_new(IDP_SOAP)?,
                SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled),
            )
            .map_err(|error| format!("{policy} rejected the request: {error:?}"))?;
        assert_eq!(received.message().destination(), None, "{policy}");
    }
    Ok(())
}

fn resigned_without_destination(sp_envelope: &str) -> Result<String, Box<dyn std::error::Error>> {
    let envelope = Document::parse(sp_envelope)?;
    let authn = envelope
        .descendants()
        .find(|node| node.has_tag_name((PROTOCOL_NS, "AuthnRequest")))
        .ok_or("AuthnRequest missing")?;
    let signed = &sp_envelope[authn.range()];
    let request = Document::parse(signed)?;
    let root = request.root_element();
    let destination = root
        .attributes()
        .find(|attribute| attribute.name() == "Destination")
        .ok_or("Destination missing")?
        .range();
    let signature = root
        .children()
        .find(|node| node.has_tag_name((DSIG_NS, "Signature")))
        .ok_or("signature missing")?
        .range();
    let unsigned = format!(
        "{}{}{}",
        &signed[..destination.start],
        &signed[destination.end..signature.start],
        &signed[signature.end..],
    );
    let key = read_private_key(PRIVKEY, None)?;
    let resigned = sign_saml_xml(&unsigned, true, &key, CERT, RSA_SHA256, &[], None)?;
    Ok(format!(
        r#"<soap:Envelope xmlns:soap="{SOAP_NS}"><soap:Body>{resigned}</soap:Body></soap:Envelope>"#
    ))
}
