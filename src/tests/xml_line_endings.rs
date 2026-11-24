#![cfg(crypto)]

use super::common;
use super::post_validation::post_validation;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::{keys::read_private_key, sign_saml_xml};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeValue, Attributes,
    AudienceValidationPolicy, EntityId, FormField, IdentityProvider, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, Inbound, MetadataTrustPolicy, NameId, NameIdFormat, PendingAuthnRequest,
    ReplayPolicy, RespondSso, SamlError, SamlValidationContext, ServiceProvider, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint, SsoSession, StartSso,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const NAME_ID: &str = "alice\nx";
const ROLE: &str = "user\nadmin";

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

struct SignedExchange {
    sp: saml_rs::ServiceProvider,
    idp_descriptor: IdpDescriptor,
    pending: PendingAuthnRequest,
    fields: Vec<FormField>,
    xml: String,
}

impl SignedExchange {
    fn new() -> TestResult<Self> {
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::post(SP_ACS)?.with_default(),
            )
            .credentials(signing_credentials())
            .name_id_format(NameIdFormat::Unspecified)
            .validation(SpValidationPolicy {
                assertion_signatures: AssertionSignaturePolicy::RequireSigned,
                audience: AudienceValidationPolicy::RequireRestriction,
                ..SpValidationPolicy::default()
            })
            .build()?,
        );
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .credentials(signing_credentials())
            .validation(IdpValidationPolicy::default())
            .build()?,
        );
        let sp_descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?;
        let idp_descriptor = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?;

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let received = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let role = Attribute::new("role", vec![AttributeValue::new(ROLE)]);
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(NameId::new(NAME_ID)).attributes(Attributes::new(vec![role])),
            RespondSso::post(),
        )?;
        let fields = response.post_form()?.fields().to_vec();
        let encoded = fields
            .iter()
            .find(|field| field.name() == "SAMLResponse")
            .map(FormField::value)
            .ok_or("missing SAMLResponse")?;
        let xml = String::from_utf8(STANDARD.decode(encoded)?)?;
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
                "SAMLResponse" => FormField::new("SAMLResponse", STANDARD.encode(xml.as_bytes())),
                _ => field.clone(),
            })
            .collect();
        self.sp.finish_sso(
            &self.idp_descriptor,
            &self.pending,
            Inbound::post(fields),
            post_validation(&mut Default::default()),
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
        let key = read_private_key(PRIVKEY, None)?;
        let signed = sign_saml_xml(
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
