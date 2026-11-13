//! XML 1.0 end-of-line handling of signed text through the typed Web Browser
//! SSO flow.
//!
//! XML 1.0 Fifth Edition §2.11 passes a single line feed to the application
//! for a literal carriage return and line feed pair and for a lone carriage
//! return. The `&#xD;` character reference stays a carriage return.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{construct_saml_signature, keys::load_private_key};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeValue, Attributes,
    AudienceValidationPolicy, AuthnRequest, BrowserInput, EntityId, FormField, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, PendingAuthnRequest,
    ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, SsoResponse, SsoSession, StartSso, Subject,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const NAME_ID: &str = "alice\nx";
const ROLE: &str = "user\nadmin";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

struct SignedExchange {
    sp: Saml<saml_rs::Sp>,
    idp_descriptor: IdpDescriptor,
    pending: PendingAuthnRequest,
    fields: Vec<FormField>,
    xml: String,
}

impl SignedExchange {
    fn new() -> TestResult<Self> {
        let sp = Saml::sp(
            SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
                .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
                .credentials(signing_credentials())
                .validation(SpValidationPolicy {
                    assertions: AssertionSignaturePolicy::RequireSigned,
                    audience: AudienceValidationPolicy::Validate,
                    ..SpValidationPolicy::recommended()
                })
                .build()?,
        )?;
        let idp = Saml::idp(
            IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
                .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
                .credentials(signing_credentials())
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

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let received = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let role = Attribute::new("role", None, vec![AttributeValue::new(ROLE)]);
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            Subject::new(NameId::new(NAME_ID, None), Vec::new()),
            RespondSso::post().attributes(Attributes::new(vec![role])),
        )?;
        let fields = response.post_form()?.fields().to_vec();
        let encoded = fields
            .iter()
            .find(|field| field.name() == "SAMLResponse")
            .map(FormField::value)
            .ok_or("missing SAMLResponse")?;
        let xml = String::from_utf8(base64_decode(encoded)?)?;
        if xml.matches('\n').count() != 2 || xml.contains('\r') {
            return Err("expected the two signed line feeds and no carriage return".into());
        }

        Ok(Self {
            sp,
            idp_descriptor,
            pending: started.pending,
            fields,
            xml,
        })
    }

    fn finish(&self, xml: &str) -> Result<SsoSession, SamlError> {
        let fields = self
            .fields
            .iter()
            .map(|field| match field.name() {
                "SAMLResponse" => FormField::new("SAMLResponse", base64_encode(xml.as_bytes())),
                _ => field.clone(),
            })
            .collect();
        self.sp.finish_sso(
            &self.idp_descriptor,
            &self.pending,
            BrowserInput::<SsoResponse>::post(fields),
            validation(),
        )
    }

    fn respelled(&self, line_ending: &str) -> Result<SsoSession, SamlError> {
        self.finish(&self.xml.replace('\n', line_ending))
    }

    fn resigned(&self, line_ending: &str) -> TestResult<SsoSession> {
        let start = self.xml.find("<ds:Signature").ok_or("missing signature")?;
        let end = self
            .xml
            .find("</ds:Signature>")
            .ok_or("unterminated signature")?
            + "</ds:Signature>".len();
        let unsigned = format!("{}{}", &self.xml[..start], &self.xml[end..]);
        let key = load_private_key(PRIVKEY, None)?;
        let signed = construct_saml_signature(
            &unsigned.replace('\n', line_ending),
            false,
            &key,
            CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        Ok(self.finish(&signed)?)
    }
}

fn role_values(session: &SsoSession) -> TestResult<Vec<&str>> {
    Ok(session
        .attributes()
        .get("role")
        .ok_or("missing role attribute")?
        .values()
        .iter()
        .map(AttributeValue::as_str)
        .collect())
}

#[test]
fn signed_text_line_endings_reach_the_model_as_line_feeds() -> TestResult {
    let exchange = SignedExchange::new()?;

    for line_ending in ["\n", "\r\n", "\r"] {
        let session = exchange.respelled(line_ending)?;

        assert_eq!(session.name_id().value(), NAME_ID, "{line_ending:?}");
        assert_eq!(role_values(&session)?, [ROLE], "{line_ending:?}");
    }
    Ok(())
}

#[test]
fn signed_line_feed_changed_to_another_value_fails_verification() -> TestResult {
    let exchange = SignedExchange::new()?;

    for line_ending in ["&#xD;", "&#xD;\n", "\r\r", "\n\n", ""] {
        let result = exchange.respelled(line_ending);

        assert!(
            matches!(result, Err(SamlError::SignatureVerification { .. })),
            "{line_ending:?}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn signed_carriage_return_reference_reaches_the_model_as_a_carriage_return() -> TestResult {
    let exchange = SignedExchange::new()?;

    for (line_ending, value) in [("&#xD;", "\r"), ("&#xD;\r\n", "\r\n"), ("&#xD;\r", "\r\n")] {
        let session = exchange.resigned(line_ending)?;

        assert_eq!(
            session.name_id().value(),
            NAME_ID.replace('\n', value),
            "{line_ending:?}"
        );
        assert_eq!(
            role_values(&session)?,
            [ROLE.replace('\n', value)],
            "{line_ending:?}"
        );
    }
    Ok(())
}
