#![cfg(crypto)]

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::namespace::{ASSERTION, PROTOCOL};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::{
    AcsEndpoint, Attribute, AttributeValue, AuthnRequest, EntityId, FormField, IdentityProvider,
    IdpConfig, IdpDescriptor, InMemoryReplayCache, Inbound, MetadataTrustPolicy, Received,
    ReplayPolicy, SamlError, SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor,
    SsoEndpoint, SsoSession,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::common::signing_credentials;

const SP: &str = "https://sp.example.com/metadata";
const IDP: &str = "https://idp.example.com/metadata";
const ACS: &str = "https://sp.example.com/acs";
const SSO: &str = "https://idp.example.com/sso";
const ISSUE_INSTANT: &str = "2026-07-15T12:00:00Z";
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");

fn validation_time() -> Result<SystemTime, time::error::Parse> {
    OffsetDateTime::parse("2026-07-15T12:01:00Z", &Rfc3339).map(SystemTime::from)
}

fn receive_authn_request(xml: &str) -> Result<Received<AuthnRequest>, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP)?, AcsEndpoint::post(ACS)?).build()?,
    );
    let peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(EntityId::try_new(IDP)?, SsoEndpoint::post(SSO)?).build()?,
    );
    Ok(idp.receive_sso(
        &peer,
        Inbound::post(vec![FormField::new("SAMLRequest", STANDARD.encode(xml))]),
        SamlValidationContext::new(validation_time()?, ReplayPolicy::NoCache),
    )?)
}

#[test]
fn identity_provider_reads_normalized_authn_request_namespace_declarations(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:pr&#x6f;tocol"
             ID="_login" Version="2.0" IssueInstant="{ISSUE_INSTANT}" Destination="{SSO}">
             <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:asserti&#111;n">{SP}</Issuer>
           </p:AuthnRequest>"#,
    );

    let receipt = receive_authn_request(&xml)?;

    assert_eq!(receipt.message().id().as_str(), "_login");
    assert_eq!(receipt.message().issuer().as_str(), SP);
    Ok(())
}

#[test]
fn identity_provider_retains_a_requested_subject_confirmation_with_a_foreign_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL}" xmlns:a="{ASSERTION}"
             ID="_login" Version="2.0" IssueInstant="{ISSUE_INSTANT}" Destination="{SSO}">
             <a:Issuer>{SP}</a:Issuer>
             <a:Subject><a:NameID>alice@example.com</a:NameID>
               <a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                 <a:SubjectConfirmationData xmlns:ext="urn:example:directory"
                   ext:Recipient="directory-team"/>
               </a:SubjectConfirmation>
             </a:Subject>
           </p:AuthnRequest>"#,
    );

    let receipt = receive_authn_request(&xml)?;
    let subject = receipt
        .message()
        .requested_subject()
        .ok_or("missing requested Subject")?;
    let [confirmation] = subject.confirmations() else {
        return Err("expected one requested subject confirmation".into());
    };
    assert!(confirmation
        .raw_xml()
        .contains(r#"ext:Recipient="directory-team""#));
    Ok(())
}

fn accept_signed_response(
    bearer_extensions: &str,
    attribute_attributes: &str,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP)?, AcsEndpoint::post(ACS)?).build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(EntityId::try_new(IDP)?, SsoEndpoint::post(SSO)?)
            .credentials(signing_credentials())
            .build()?,
    );
    let peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let xml = format!(
        r#"<p:Response xmlns:p="{PROTOCOL}" xmlns:a="{ASSERTION}" xmlns:ext="urn:example:directory"
             ID="_response" Version="2.0" IssueInstant="{ISSUE_INSTANT}" Destination="{ACS}">
             <a:Issuer>{IDP}</a:Issuer>
             <p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status>
             <a:Assertion ID="_assertion" Version="2.0" IssueInstant="{ISSUE_INSTANT}">
               <a:Issuer>{IDP}</a:Issuer>
               <a:Subject><a:NameID>alice@example.com</a:NameID>
                 <a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                   <a:SubjectConfirmationData {bearer_extensions}
                     Recipient="{ACS}" NotOnOrAfter="2026-07-15T12:10:00Z"/>
                 </a:SubjectConfirmation>
               </a:Subject>
               <a:Conditions><a:AudienceRestriction><a:Audience>{SP}</a:Audience></a:AudienceRestriction></a:Conditions>
               <a:AuthnStatement AuthnInstant="{ISSUE_INSTANT}">
                 <a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext>
               </a:AuthnStatement>
               <a:AttributeStatement>
                 <a:Attribute {attribute_attributes}>
                   <a:AttributeValue>alice@example.com</a:AttributeValue>
                 </a:Attribute>
               </a:AttributeStatement>
             </a:Assertion>
           </p:Response>"#,
    );
    let key = read_private_key(KEY, None)?;
    let signed = sign_saml_xml(&xml, true, &key, CERT, RSA_SHA256, &[], None)?;
    let now = validation_time()?;
    let mut cache = InMemoryReplayCache::with_clock(move || now);
    Ok(sp.accept_unsolicited_sso(
        &peer,
        Inbound::post(vec![FormField::new(
            "SAMLResponse",
            STANDARD.encode(signed),
        )]),
        SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache)),
    )?)
}

#[test]
fn service_provider_reads_only_saml_bearer_fields_for_acceptance_and_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_signed_response(
        r#"ext:Recipient="directory-team" ext:InResponseTo="directory-lookup" ext:NotOnOrAfter="next-sync""#,
        r#"Name="mail""#,
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn service_provider_reads_the_saml_attribute_name_and_ignores_foreign_annotations(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_signed_response(
        "",
        r#"ext:Name="emailAddress" ext:FriendlyName="Email Address" ext:NameFormat="directory" Name="mail""#,
    )?;
    assert_eq!(
        session.attributes().as_slice(),
        &[Attribute::new(
            "mail",
            [AttributeValue::new("alice@example.com")]
        )],
    );
    Ok(())
}

#[test]
fn service_provider_requires_the_saml_attribute_name() -> Result<(), Box<dyn std::error::Error>> {
    let result = accept_signed_response("", r#"ext:Name="emailAddress""#);
    let error = result.err().ok_or("the response was accepted")?;
    assert!(
        matches!(error.downcast_ref::<SamlError>(), Some(SamlError::ProtocolProfile(message))
            if message == "Attribute is missing required unqualified attribute Name"),
        "{error}"
    );
    Ok(())
}
