//! Typed SSO comparison of a success `<Response>` `<Issuer>` with the identity provider.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{construct_saml_signature, keys::load_private_key};
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, Outbound,
    PendingAuthnRequest, PrivateKeyPem, ReplayPolicy, RespondSso, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse,
    SsoSession, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const FOREIGN_ISSUER: &str = "https://attacker.example/idp";
const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Exchange {
    sp: Saml<saml_rs::Sp>,
    idp_descriptor: IdpDescriptor,
    pending: Option<PendingAuthnRequest>,
    response_fields: Vec<FormField>,
}

#[derive(Clone, Copy)]
enum Delivery {
    Solicited,
    Unsolicited,
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn exchange(delivery: Delivery) -> TestResult<Exchange> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let (pending, response) = match delivery {
        Delivery::Unsolicited => (
            None,
            idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?,
        ),
        Delivery::Solicited => {
            let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
            let received = idp.receive_sso(
                &sp_descriptor,
                BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
                validation(),
            )?;
            let response =
                idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
            (Some(started.pending), response)
        }
    };
    Ok(Exchange {
        sp,
        idp_descriptor,
        pending,
        response_fields: post_fields(&response)?,
    })
}

fn response_xml(fields: &[FormField]) -> TestResult<String> {
    let encoded = fields
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(base64_decode(encoded)?)?)
}

fn strip_embedded_signatures(xml: &str) -> TestResult<String> {
    let mut rest = xml;
    let mut stripped = String::new();
    while let Some(start) = rest.find("<ds:Signature") {
        stripped.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find("</ds:Signature>")
            .ok_or("unterminated XML signature")?;
        rest = &after[end + "</ds:Signature>".len()..];
    }
    stripped.push_str(rest);
    Ok(stripped)
}

fn assertion_signed_with_response_issuer(exchange: &Exchange, issuer: &str) -> TestResult<String> {
    let xml = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?.replacen(
        &format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"),
        issuer,
        1,
    );
    let key = load_private_key(PRIVKEY, None)?;
    Ok(construct_saml_signature(
        &xml,
        false,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn accept(exchange: &Exchange, xml: &str) -> Result<SsoSession, SamlError> {
    let input = BrowserInput::<SsoResponse>::post(vec![FormField::new(
        "SAMLResponse",
        base64_encode(xml.as_bytes()),
    )]);
    match &exchange.pending {
        Some(pending) => {
            exchange
                .sp
                .finish_sso(&exchange.idp_descriptor, pending, input, validation())
        }
        None => exchange
            .sp
            .accept_unsolicited_sso(&exchange.idp_descriptor, input, validation()),
    }
}

#[test]
fn a_foreign_response_issuer_is_rejected_on_success() -> TestResult {
    for delivery in [Delivery::Solicited, Delivery::Unsolicited] {
        let exchange = exchange(delivery)?;
        let own = format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>");
        let control = assertion_signed_with_response_issuer(&exchange, &own)?;
        assert_eq!(
            accept(&exchange, &control)?.name_id().value(),
            "alice@example.com"
        );

        let foreign = format!("<saml:Issuer>{FOREIGN_ISSUER}</saml:Issuer>");
        let xml = assertion_signed_with_response_issuer(&exchange, &foreign)?;
        match accept(&exchange, &xml) {
            Err(SamlError::IssuerMismatch { expected, actual }) => {
                assert_eq!(expected, IDP_ENTITY_ID);
                assert_eq!(actual.as_deref(), Some(FOREIGN_ISSUER));
            }
            other => return Err(format!("expected IssuerMismatch, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn two_response_issuers_are_rejected_on_success() -> TestResult {
    let exchange = exchange(Delivery::Solicited)?;
    let own = format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>");
    let xml = assertion_signed_with_response_issuer(&exchange, &format!("{own}{own}"))?;
    match accept(&exchange, &xml) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(actual, None);
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn a_success_response_without_an_issuer_is_accepted() -> TestResult {
    let exchange = exchange(Delivery::Solicited)?;
    let xml = assertion_signed_with_response_issuer(&exchange, "")?;
    assert_eq!(
        accept(&exchange, &xml)?.name_id().value(),
        "alice@example.com"
    );
    Ok(())
}
