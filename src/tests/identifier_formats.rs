//! Attribute name formats, name identifier formats, entity identifiers, and
//! persistent and transient name identifiers, through the typed identity-provider and
//! service-provider flows.
//!
//! SAML Core §1.3.2, §8.2, §8.3.6, §8.3.7 and §8.3.8, with Conformance Requirements
//! §3.3 and Approved Errata 05 E78 and E86. The producer rules bind the party
//! that generates an identifier. A receiver parses a peer's identifier and does
//! not reject it for missing one of them.
#![cfg(crypto)]

use super::common;
use super::post_validation::post_validation;
use saml_rs::tests::engine::{IdpMessages, SpMessages};

use common::signing_credentials;

use std::time::SystemTime;

use crate::tests::template::fill_template;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::name_id_format::{PERSISTENT, TRANSIENT};
use saml_rs::constants::Binding;
use saml_rs::entity::iso8601_offset;
use saml_rs::entity::User;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadataInput, SpMetadataInput,
};
use saml_rs::sp::LoginRequestOptions;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeNameFormat, AttributeValue,
    Attributes, AudienceValidationPolicy, EntityId, FormField, IdentityProvider, IdpConfig,
    IdpConfigBuilder, IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, NameId,
    NameIdFormat, Outbound, ReplayPolicy, RequestedSubjectIdentifier, RespondSso, SamlError,
    SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoAssertion, SsoEndpoint, SsoResponse, SsoSession, StartSso,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";

const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
const URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
const DEPLOYMENT_FORMAT: &str = "https://example.com/attribute-name-format";
const MAIL_OID: &str = "urn:oid:0.9.2342.19200300.100.1.3";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp() -> Result<saml_rs::ServiceProvider, SamlError> {
    let validation = SpValidationPolicy {
        assertion_signatures: AssertionSignaturePolicy::RequireSigned,
        audience: AudienceValidationPolicy::RequireRestriction,
        ..Default::default()
    };
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(signing_credentials())
        .name_id_format(NameIdFormat::Unspecified)
        .validation(validation)
        .build()?,
    ))
}

fn idp_config() -> Result<IdpConfigBuilder, SamlError> {
    Ok(IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .credentials(signing_credentials())
    .validation(IdpValidationPolicy::default()))
}

fn idp() -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(idp_config()?.build()?))
}

fn descriptors(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
    ))
}

pub(super) fn alice() -> NameId {
    NameId::new("alice@example.com")
}

fn response_xml(outbound: &Outbound<SsoResponse>) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = outbound
        .post_form()?
        .fields()
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(STANDARD.decode(encoded)?)?)
}

fn attribute_tag<'a>(xml: &'a str, name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let needle = format!("<saml:Attribute Name=\"{name}\"");
    let start = xml
        .find(&needle)
        .ok_or_else(|| format!("missing Attribute {name}: {xml}"))?;
    let rest = &xml[start..];
    let end = rest.find('>').ok_or("unterminated Attribute tag")?;
    Ok(&rest[..=end])
}

fn name_id_element(xml: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let start = xml.find("<saml:NameID").ok_or("missing NameID")?;
    let rest = &xml[start..];
    let end = rest.find("</saml:NameID>").ok_or("missing NameID end")?;
    Ok(&rest[..end])
}

pub(super) struct Exchange {
    pub(super) xml: String,
    pub(super) session: SsoSession,
}

pub(super) fn exchange(
    assertion: SsoAssertion,
    options: RespondSso,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(&sp_descriptor, &received, assertion, options)?;
    let xml = response_xml(&response)?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    Ok(Exchange { xml, session })
}

pub(super) fn respond(
    assertion: SsoAssertion,
    options: RespondSso,
) -> Result<Outbound<SsoResponse>, SamlError> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    idp.initiate_sso(&sp_descriptor, assertion, options)
}

pub(super) fn values(values: &[&str]) -> Vec<AttributeValue> {
    values.iter().copied().map(AttributeValue::new).collect()
}

fn attribute<'a>(
    session: &'a SsoSession,
    name: &str,
) -> Result<&'a Attribute, Box<dyn std::error::Error>> {
    session
        .attributes()
        .get(name)
        .ok_or_else(|| format!("missing attribute {name}").into())
}

#[test]
fn attribute_name_format_identifiers_are_the_core_uris() {
    assert_eq!(AttributeNameFormat::Unspecified.as_uri(), UNSPECIFIED);
    assert_eq!(AttributeNameFormat::Uri.as_uri(), URI);
    assert_eq!(AttributeNameFormat::Basic.as_uri(), BASIC);
    assert_eq!(
        AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()).as_uri(),
        DEPLOYMENT_FORMAT
    );
}

#[test]
fn identity_provider_produces_and_service_provider_consumes_each_attribute_name_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let attributes = Attributes::new(vec![
        Attribute::new("displayName", values(&["Alice Example"]))
            .with_name_format(AttributeNameFormat::Unspecified),
        Attribute::new(MAIL_OID, values(&["a@example.com"]))
            .with_name_format(AttributeNameFormat::Uri)
            .with_friendly_name("mail"),
        Attribute::new("eduPersonAffiliation", values(&["member", "staff"]))
            .with_name_format(AttributeNameFormat::Basic),
        Attribute::new("role", values(&["admin"]))
            .with_name_format(AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string())),
        Attribute::new("locale", values(&["en"])),
        Attribute::new("groups", Vec::new()),
    ]);

    let exchange = exchange(
        SsoAssertion::new(alice()).attributes(attributes),
        RespondSso::post(),
    )?;

    for (name, format) in [
        ("displayName", UNSPECIFIED),
        (MAIL_OID, URI),
        ("eduPersonAffiliation", BASIC),
        ("role", DEPLOYMENT_FORMAT),
    ] {
        let tag = attribute_tag(&exchange.xml, name)?;
        assert!(tag.contains(&format!("NameFormat=\"{format}\"")), "{tag}");
    }
    assert!(!attribute_tag(&exchange.xml, "locale")?.contains("NameFormat"));
    assert!(attribute_tag(&exchange.xml, MAIL_OID)?.contains("FriendlyName=\"mail\""));
    assert_eq!(
        attribute_tag(&exchange.xml, "groups")?,
        "<saml:Attribute Name=\"groups\"/>"
    );
    assert_eq!(exchange.xml.matches("<saml:AttributeStatement>").count(), 1);

    for (name, format, expected) in [
        (
            "displayName",
            AttributeNameFormat::Unspecified,
            vec!["Alice Example"],
        ),
        (MAIL_OID, AttributeNameFormat::Uri, vec!["a@example.com"]),
        (
            "eduPersonAffiliation",
            AttributeNameFormat::Basic,
            vec!["member", "staff"],
        ),
        (
            "role",
            AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()),
            vec!["admin"],
        ),
    ] {
        let consumed = attribute(&exchange.session, name)?;
        assert_eq!(consumed.name_format(), Some(&format), "{name}");
        assert_eq!(
            consumed
                .values()
                .iter()
                .map(AttributeValue::as_str)
                .collect::<Vec<_>>(),
            expected,
            "{name}"
        );
    }
    let locale = attribute(&exchange.session, "locale")?;
    assert_eq!(locale.name_format(), None);
    assert_eq!(locale.values(), values(&["en"]).as_slice());
    assert_eq!(
        attribute(&exchange.session, MAIL_OID)?.friendly_name(),
        Some("mail")
    );
    assert_eq!(locale.friendly_name(), None);
    Ok(())
}

#[test]
fn signed_sso_preserves_xml_characters_in_attribute_names_formats_and_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let attribute = Attribute::new("Research & \"Development\"", values(&["5 < 7 & 9 > 3"]))
        .with_name_format(AttributeNameFormat::Custom(
            "urn:groups:research&design".into(),
        ));
    let exchange = exchange(
        SsoAssertion::new(alice()).attributes(Attributes::new([attribute.clone()])),
        RespondSso::post().sign_response(),
    )?;
    assert_eq!(exchange.xml.matches("<saml:AttributeValue ").count(), 1);
    assert_eq!(exchange.session.attributes().as_slice(), [attribute]);
    Ok(())
}

#[test]
fn unsolicited_response_carries_attribute_name_formats_and_a_generated_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let name_id = NameId::generate_transient();
    let mail = Attribute::new(MAIL_OID, values(&["a@example.com"]))
        .with_name_format(AttributeNameFormat::Uri);

    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(name_id.clone()).attributes(Attributes::new(vec![mail.clone()])),
        RespondSso::post(),
    )?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;

    assert_eq!(session.name_id(), &name_id);
    assert_eq!(session.attributes().as_slice(), [mail]);
    Ok(())
}

#[test]
fn response_without_typed_attributes_has_no_attribute_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    for assertion in [
        SsoAssertion::new(alice()),
        SsoAssertion::new(alice()).attributes(Attributes::default()),
    ] {
        let exchange = exchange(assertion, RespondSso::post())?;
        assert!(!exchange.xml.contains("AttributeStatement"));
        assert!(exchange.session.attributes().as_slice().is_empty());
    }
    Ok(())
}

#[test]
fn identity_provider_does_not_generate_a_basic_attribute_whose_name_is_not_an_xml_name(
) -> Result<(), Box<dyn std::error::Error>> {
    for name in ["", "given name", "1stName", "a<b", "-mail"] {
        let attributes = Attributes::new(vec![
            Attribute::new(name, values(&["x"])).with_name_format(AttributeNameFormat::Basic)
        ]);
        match respond(
            SsoAssertion::new(alice()).attributes(attributes),
            RespondSso::post(),
        ) {
            Err(SamlError::Invalid(message)) if message.contains("basic") => {}
            other => {
                return Err(format!("expected basic name error for {name:?}, got {other:?}").into())
            }
        }
    }
    let spelled_out = Attribute::new("given name", values(&["x"]))
        .with_name_format(AttributeNameFormat::Custom(BASIC.to_string()));
    assert_eq!(spelled_out.name_format(), Some(&AttributeNameFormat::Basic));
    match respond(
        SsoAssertion::new(alice()).attributes(Attributes::new([spelled_out])),
        RespondSso::post(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("basic") => {}
        other => return Err(format!("expected basic name error, got {other:?}").into()),
    }
    for name in ["mail", "_mail", "ns:mail", "given-name.1", "é"] {
        let attributes = Attributes::new(vec![
            Attribute::new(name, values(&["x"])).with_name_format(AttributeNameFormat::Basic)
        ]);
        respond(
            SsoAssertion::new(alice()).attributes(attributes),
            RespondSso::post(),
        )?;
    }
    for format in [
        AttributeNameFormat::Unspecified,
        AttributeNameFormat::Uri,
        AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()),
    ] {
        let attributes = Attributes::new(vec![
            Attribute::new("given name", values(&["x"])).with_name_format(format)
        ]);
        respond(
            SsoAssertion::new(alice()).attributes(attributes),
            RespondSso::post(),
        )?;
    }
    Ok(())
}

fn accept_peer_attributes(
    attributes: &[(&str, &str, &str)],
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let mut writer = crate::xml::write::XmlWriter::new();
    writer.start("saml:AttributeStatement", &[]);
    for &(name, format, value) in attributes {
        writer.start("saml:Attribute", &[("Name", name), ("NameFormat", format)]);
        writer.text_element("saml:AttributeValue", &[], value);
        writer.end("saml:Attribute");
    }
    writer.end("saml:AttributeStatement");
    accept_peer_attribute_statement(&writer.finish())
}

pub(super) fn accept_peer_attribute_statement(
    statement: &str,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    accept_peer_response(
        &NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress),
        statement,
    )
}

#[test]
fn service_provider_rejects_an_attribute_without_a_name() -> Result<(), Box<dyn std::error::Error>>
{
    let error = accept_peer_attribute_statement(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"mail\"><saml:AttributeValue>a@example.com</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>",
    )
    .err()
    .ok_or("the response was accepted")?;

    assert!(
        matches!(
            error.downcast_ref::<SamlError>(),
            Some(SamlError::ProtocolProfile(message))
                if message == "Attribute is missing required unqualified attribute Name"
        ),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn service_provider_accepts_an_attribute_whose_name_is_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attribute_statement(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>",
    )?;

    assert_eq!(
        session.attributes().as_slice(),
        [Attribute::new("", values(&["admin"]))]
    );
    Ok(())
}

#[test]
fn service_provider_accepts_a_basic_attribute_whose_name_is_not_an_xml_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attributes(&[("given name", BASIC, "Alice")])?;
    let given_name = attribute(&session, "given name")?;
    assert_eq!(given_name.name_format(), Some(&AttributeNameFormat::Basic));
    assert_eq!(given_name.values(), values(&["Alice"]).as_slice());
    Ok(())
}

#[test]
fn service_provider_reports_the_name_format_of_each_peer_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attributes(&[
        ("uid", UNSPECIFIED, "alice"),
        (MAIL_OID, URI, "a@example.com"),
        ("eduPersonAffiliation", BASIC, "member"),
        ("eduPersonAffiliation", BASIC, "staff"),
        ("role", DEPLOYMENT_FORMAT, "admin"),
    ])?;

    assert_eq!(
        session.attributes().as_slice(),
        [
            Attribute::new("uid", values(&["alice"]))
                .with_name_format(AttributeNameFormat::Unspecified),
            Attribute::new(MAIL_OID, values(&["a@example.com"]))
                .with_name_format(AttributeNameFormat::Uri),
            Attribute::new("eduPersonAffiliation", values(&["member", "staff"]))
                .with_name_format(AttributeNameFormat::Basic),
            Attribute::new("role", values(&["admin"]))
                .with_name_format(AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string())),
        ]
    );
    Ok(())
}

#[test]
fn service_provider_keeps_one_attribute_for_each_name_and_name_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attributes(&[("role", URI, "admin"), ("role", BASIC, "auditor")])?;

    assert_eq!(
        session.attributes().as_slice(),
        [
            Attribute::new("role", values(&["admin"])).with_name_format(AttributeNameFormat::Uri),
            Attribute::new("role", values(&["auditor"]))
                .with_name_format(AttributeNameFormat::Basic),
        ]
    );
    Ok(())
}

#[test]
fn service_provider_reads_a_name_format_by_its_schema_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let padded_uri = format!(" {URI}\t ");
    let padded_deployment_format = format!("\n{DEPLOYMENT_FORMAT} ");
    let session = accept_peer_attributes(&[
        ("role", &padded_uri, "admin"),
        ("role", URI, "auditor"),
        ("role", &padded_deployment_format, "owner"),
        ("role", DEPLOYMENT_FORMAT, "viewer"),
    ])?;

    assert_eq!(
        session.attributes().as_slice(),
        [
            Attribute::new("role", values(&["admin", "auditor"]))
                .with_name_format(AttributeNameFormat::Uri),
            Attribute::new("role", values(&["owner", "viewer"]))
                .with_name_format(AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string())),
        ]
    );
    Ok(())
}

#[test]
fn service_provider_keeps_every_value_of_repeated_attribute_elements(
) -> Result<(), Box<dyn std::error::Error>> {
    let attributes = Attributes::new(vec![
        Attribute::new("role", values(&["a1"]))
            .with_name_format(AttributeNameFormat::Basic)
            .with_friendly_name("Role"),
        Attribute::new("role", values(&["b1", "b2"]))
            .with_name_format(AttributeNameFormat::Basic)
            .with_friendly_name("Roles"),
        Attribute::new("group", values(&["g1", "g2"])).with_name_format(AttributeNameFormat::Basic),
        Attribute::new("group", values(&["g3"])).with_name_format(AttributeNameFormat::Basic),
        Attribute::new("uid", values(&["alice"])),
        Attribute::new("uid", values(&["al"]))
            .with_name_format(AttributeNameFormat::Unspecified)
            .with_friendly_name("User ID"),
        Attribute::new("uid", values(&["0001"]))
            .with_name_format(AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string())),
    ]);

    let exchange = exchange(
        SsoAssertion::new(alice()).attributes(attributes),
        RespondSso::post(),
    )?;

    assert_eq!(
        exchange.session.attributes().as_slice(),
        [
            Attribute::new("role", values(&["a1", "b1", "b2"]))
                .with_name_format(AttributeNameFormat::Basic)
                .with_friendly_name("Role"),
            Attribute::new("group", values(&["g1", "g2", "g3"]))
                .with_name_format(AttributeNameFormat::Basic),
            Attribute::new("uid", values(&["alice", "al"])),
            Attribute::new("uid", values(&["0001"]))
                .with_name_format(AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string())),
        ]
    );
    Ok(())
}

#[test]
fn identity_provider_does_not_generate_a_name_format_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    for name_format in [
        "",
        "  ",
        "not a uri",
        "attribute-name-format",
        "/relative/path",
    ] {
        let attribute = Attribute::new("role", values(&["admin"]))
            .with_name_format(AttributeNameFormat::Custom(name_format.to_string()));
        match respond(
            SsoAssertion::new(alice()).attributes(Attributes::new([attribute])),
            RespondSso::post(),
        ) {
            Err(SamlError::Invalid(message)) if message.contains("NameFormat") => {}
            Err(other) => return Err(other.into()),
            Ok(_) => return Err(format!("NameFormat {name_format:?} was written").into()),
        }
    }
    Ok(())
}

fn assert_opaque_identifier(value: &str) {
    assert_eq!(value.len(), 41, "{value}");
    assert!(value.starts_with('_'), "{value}");
    assert!(
        value[1..]
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f')),
        "{value}"
    );
    assert!(value.chars().count() <= 256);
}

#[test]
fn generated_request_response_and_assertion_ids_have_160_random_bits(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange(SsoAssertion::new(alice()), RespondSso::post())?;
    let request_id = exchange
        .session
        .in_response_to()
        .ok_or("the solicited response has no InResponseTo")?;
    let response_id = exchange.session.response_id().as_str();
    let assertion_id = exchange.session.assertion_id().as_str();

    for id in [request_id.as_str(), response_id, assertion_id] {
        assert_opaque_identifier(id);
    }
    assert_ne!(response_id, assertion_id);
    Ok(())
}

#[test]
fn generated_transient_and_persistent_identifiers_follow_the_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let generators: [(fn() -> NameId, NameIdFormat); 2] = [
        (NameId::generate_transient, NameIdFormat::Transient),
        (NameId::generate_persistent, NameIdFormat::Persistent),
    ];
    for (generate, format) in generators {
        let name_id = generate();
        assert_eq!(name_id.format(), Some(&format));
        assert_opaque_identifier(name_id.value());
        assert_eq!(name_id.name_qualifier(), None);
        assert_eq!(name_id.sp_name_qualifier(), None);
        assert_eq!(name_id.sp_provided_id(), None);
        assert_ne!(name_id.value(), generate().value());

        let exchange = exchange(SsoAssertion::new(name_id.clone()), RespondSso::post())?;
        assert_eq!(
            name_id_element(&exchange.xml)?,
            format!(
                "<saml:NameID Format=\"{}\">{}",
                format.as_uri(),
                name_id.value()
            )
        );
        assert_eq!(exchange.session.name_id(), &name_id);
    }
    Ok(())
}

#[test]
fn stored_persistent_identifier_is_reissued_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let stored = NameId::generate_persistent().value().to_string();

    let first = exchange(
        SsoAssertion::new(NameId::persistent(stored.clone())?),
        RespondSso::post(),
    )?;
    let second = exchange(
        SsoAssertion::new(NameId::persistent(stored.clone())?),
        RespondSso::post(),
    )?;

    for exchange in [first, second] {
        assert_eq!(exchange.session.name_id().value(), stored);
        assert_eq!(
            exchange.session.name_id().format(),
            Some(&NameIdFormat::Persistent)
        );
    }
    Ok(())
}

#[test]
fn identity_provider_writes_the_qualifiers_and_alternative_identifier_of_the_issued_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let name_id = NameId::new(NameId::generate_persistent().value())
        .with_format(NameIdFormat::Persistent)
        .with_name_qualifier("https://origin-idp.example.com/?a=1&b=2")
        .with_sp_name_qualifier("\"affiliation\" <group>")
        .with_sp_provided_id("sp-alias");

    let exchange = exchange(SsoAssertion::new(name_id.clone()), RespondSso::post())?;

    assert_eq!(
        name_id_element(&exchange.xml)?,
        format!(
            "<saml:NameID NameQualifier=\"https://origin-idp.example.com/?a=1&amp;b=2\" SPNameQualifier=\"&quot;affiliation&quot; &lt;group&gt;\" Format=\"{}\" SPProvidedID=\"sp-alias\">{}",
            NameIdFormat::Persistent.as_uri(),
            name_id.value()
        )
    );
    assert_eq!(exchange.session.name_id(), &name_id);
    Ok(())
}

#[test]
fn stored_persistent_identifier_is_at_most_256_characters() -> Result<(), Box<dyn std::error::Error>>
{
    let longest = "é".repeat(256);
    assert_eq!(NameId::persistent(longest.clone())?.value(), longest);

    expect_name_id_length_error(NameId::persistent("é".repeat(257)))
}

fn expect_name_id_length_error<T: std::fmt::Debug>(
    result: Result<T, SamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::Invalid(message)) if message.contains("256 characters") => Ok(()),
        other => Err(format!("expected NameID length error, got {other:?}").into()),
    }
}

#[test]
fn identity_provider_does_not_issue_a_persistent_or_transient_identifier_over_256_characters(
) -> Result<(), Box<dyn std::error::Error>> {
    for format in [NameIdFormat::Persistent, NameIdFormat::Transient] {
        let longest = NameId::new("é".repeat(256)).with_format(format.clone());
        let exchange = exchange(SsoAssertion::new(longest.clone()), RespondSso::post())?;
        assert_eq!(exchange.session.name_id(), &longest);

        let too_long = NameId::new("é".repeat(257)).with_format(format);
        expect_name_id_length_error(respond(SsoAssertion::new(too_long), RespondSso::post()))?;
    }

    for format in [PERSISTENT, TRANSIENT] {
        let padded = NameIdFormat::Custom(format!("\n {format}\t"));
        let too_long = NameId::new("é".repeat(257)).with_format(padded);
        expect_name_id_length_error(respond(SsoAssertion::new(too_long), RespondSso::post()))?;
    }

    let sp = sp()?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(IdpValidationPolicy::default())
        .name_id_format(NameIdFormat::Persistent)
        .build()?,
    );
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let unformatted = NameId::new("x".repeat(257));
    expect_name_id_length_error(idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(unformatted),
        RespondSso::post(),
    ))?;

    let email = NameId::new(format!("{}@example.com", "x".repeat(300)))
        .with_format(NameIdFormat::EmailAddress);
    let exchange = exchange(SsoAssertion::new(email.clone()), RespondSso::post())?;
    assert_eq!(exchange.session.name_id(), &email);
    Ok(())
}

fn accept_peer_response(
    name_id: &NameId,
    statement: &str,
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request_id = started.pending.request_id().as_str().to_string();
    let format = name_id
        .format()
        .map(NameIdFormat::as_uri)
        .ok_or("peer NameID needs a format")?
        .to_string();
    let fill = |template: &str| -> Result<(String, String), SamlError> {
        let id = "_peer-response".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let xml = fill_template(
            template,
            &[
                ("ID", id.clone()),
                ("AssertionID", "_peer-assertion".into()),
                ("Destination", SP_ACS.into()),
                ("SubjectRecipient", SP_ACS.into()),
                ("Audience", SP_ENTITY_ID.into()),
                ("Issuer", IDP_ENTITY_ID.into()),
                ("IssueInstant", now.clone()),
                (
                    "StatusCode",
                    "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
                ),
                ("ConditionsNotBefore", now),
                ("ConditionsNotOnOrAfter", later.clone()),
                ("SubjectConfirmationDataNotOnOrAfter", later),
                ("NameIDFormat", format.clone()),
                ("NameID", name_id.value().to_string()),
                ("InResponseTo", request_id.clone()),
                ("AuthnStatement", String::new()),
            ],
        );
        Ok((id, xml.replacen("{AttributeStatement}", statement, 1)))
    };
    let context = idp
        .engine()
        .create_rendered_login_response(sp.engine(), Binding::Post, &fill)?;
    Ok(sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(vec![FormField::new("SAMLResponse", context.context)]),
        post_validation(&mut Default::default()),
    )?)
}

#[test]
fn service_provider_accepts_persistent_and_transient_identifiers_that_miss_the_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let value = format!("alice@example.com/{}", "x".repeat(300));
    for format in [NameIdFormat::Persistent, NameIdFormat::Transient] {
        let name_id = NameId::new(value.clone()).with_format(format);
        let session = accept_peer_response(&name_id, "")?;
        assert_eq!(session.name_id(), &name_id);
    }
    Ok(())
}

#[test]
fn service_provider_reads_a_name_id_format_by_its_schema_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let deployment_format = "https://example.com/name-id-format";
    for (sent, read) in [
        (format!("\n {PERSISTENT}\t"), NameIdFormat::Persistent),
        (
            format!(" {deployment_format} "),
            NameIdFormat::Custom(deployment_format.to_string()),
        ),
    ] {
        let sent = NameId::new("subject-1").with_format(NameIdFormat::Custom(sent));
        let session = accept_peer_response(&sent, "")?;
        assert_eq!(
            session.name_id(),
            &NameId::new("subject-1").with_format(read)
        );
    }
    Ok(())
}

#[test]
fn identity_provider_accepts_a_requested_identifier_that_misses_the_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let value = format!("alice@example.com/{}", "x".repeat(300));
    for format in [NameIdFormat::Persistent, NameIdFormat::Transient] {
        let sp = sp()?;
        let idp = idp()?;
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let xml = String::from_utf8(
            STANDARD.decode(
                started
                    .outbound
                    .post_form()?
                    .value("SAMLRequest")
                    .ok_or("missing SAMLRequest")?,
            )?,
        )?;
        let policy = xml
            .find("<samlp:NameIDPolicy")
            .ok_or("missing NameIDPolicy")?;
        let xml = format!(
            "{}<saml:Subject><saml:NameID Format=\"{}\">{value}</saml:NameID></saml:Subject>{}",
            &xml[..policy],
            format.as_uri(),
            &xml[policy..]
        );
        let received = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(vec![FormField::new(
                "SAMLRequest",
                STANDARD.encode(xml.as_bytes()),
            )]),
            validation(),
        )?;
        let requested = received
            .message()
            .requested_subject()
            .ok_or("missing requested subject")?;
        assert_eq!(
            requested.identifier(),
            &RequestedSubjectIdentifier::NameId(NameId::new(value.clone()).with_format(format))
        );
    }
    Ok(())
}

#[test]
fn existing_name_id_format_uris_resolve_as_before() -> Result<(), Box<dyn std::error::Error>> {
    for (format, uri) in [
        (
            NameIdFormat::EmailAddress,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        ),
        (
            NameIdFormat::Persistent,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        ),
        (
            NameIdFormat::Transient,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        ),
        (
            NameIdFormat::Entity,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
        ),
        (
            NameIdFormat::Unspecified,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        ),
        (
            NameIdFormat::Kerberos,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
        ),
        (
            NameIdFormat::WindowsDomainQualifiedName,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
        ),
        (
            NameIdFormat::X509SubjectName,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        ),
        (
            NameIdFormat::Custom("https://example.com/name-id-format".to_string()),
            "https://example.com/name-id-format",
        ),
        (
            NameIdFormat::Custom("urn:example:name-id-format".to_string()),
            "urn:example:name-id-format",
        ),
    ] {
        assert_eq!(format.as_uri(), uri);
        let name_id = NameId::new("https://idp.example.com/subjects/1").with_format(format);
        let exchange = exchange(SsoAssertion::new(name_id.clone()), RespondSso::post())?;
        assert!(
            name_id_element(&exchange.xml)?.contains(&format!("Format=\"{uri}\"")),
            "{uri}"
        );
        assert_eq!(exchange.session.name_id(), &name_id);
    }
    Ok(())
}

/// Blank, relative, and malformed values. SAML Core §1.3.2 requires a written
/// URI reference to have a non-whitespace character and to be absolute. Read
/// as an `xs:anyURI`, `urn:` has an empty opaque part, `urn:%zz` an invalid
/// escape, and `urn:a#b#c` a second `#`.
const INVALID_FORMATS: [&str; 6] = ["", "   ", "local-format", "urn:", "urn:%zz", "urn:a#b#c"];

fn expect_name_id_format_error<T>(
    result: Result<T, SamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::Invalid(message)) if message.contains("absolute URI reference") => Ok(()),
        Err(error) => Err(format!("expected NameID format error, got {error:?}").into()),
        Ok(_) => Err("expected NameID format error, got Ok".into()),
    }
}

#[test]
fn identity_provider_does_not_write_a_name_id_format_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    for format in INVALID_FORMATS {
        let name_id = NameId::new("subject-1").with_format(NameIdFormat::Custom(format.into()));
        expect_name_id_format_error(respond(SsoAssertion::new(name_id), RespondSso::post()))?;
        let mut raw_idp = idp()?.engine().clone();
        raw_idp.setting.name_id_format = vec![format.to_string()];
        expect_name_id_format_error(raw_idp.create_login_response(
            sp.engine(),
            Binding::Post,
            &User::new("subject-1"),
            &LoginResponseOptions::default(),
        ))?;
    }
    Ok(())
}

#[test]
fn identity_provider_writes_xml_markup_in_a_name_id_format_as_character_data(
) -> Result<(), Box<dyn std::error::Error>> {
    // XLink escaping maps `<`, `"`, and `>` to %3C, %22, and %3E, so the value
    // is an absolute URI reference. The XML writer escapes the markup.
    let name_id =
        NameId::new("subject-1").with_format(NameIdFormat::Custom("urn:example:a<b\"c>&d".into()));
    let exchange = exchange(SsoAssertion::new(name_id.clone()), RespondSso::post())?;
    assert!(
        name_id_element(&exchange.xml)?.contains("Format=\"urn:example:a&lt;b&quot;c&gt;&amp;d\"")
    );
    assert_eq!(exchange.session.name_id(), &name_id);
    Ok(())
}

#[test]
fn metadata_does_not_advertise_a_name_id_format_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    for format in INVALID_FORMATS {
        let custom = NameIdFormat::Custom(format.into());
        expect_name_id_format_error(
            SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
                .credentials(signing_credentials())
                .name_id_format(custom.clone())
                .build(),
        )?;
        expect_name_id_format_error(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .credentials(signing_credentials())
            .name_id_format(custom)
            .build(),
        )?;

        let formats = vec![
            NameIdFormat::EmailAddress.as_uri().to_string(),
            format.to_string(),
        ];
        let mut sp_config = raw_sp_metadata_config(SP_ENTITY_ID);
        sp_config.name_id_format = formats.clone();
        expect_name_id_format_error(generate_sp_metadata(&sp_config))?;
        let mut idp_config = raw_idp_metadata_config(IDP_ENTITY_ID);
        idp_config.name_id_format = formats;
        expect_name_id_format_error(generate_idp_metadata(&idp_config))?;
    }
    Ok(())
}

#[test]
fn metadata_is_not_generated_for_an_entity_id_that_is_not_a_uri_of_at_most_1024_characters(
) -> Result<(), Box<dyn std::error::Error>> {
    for entity_id in [
        String::new(),
        "not a uri".into(),
        format!("https://sp.example.com/{}", "a".repeat(1002)),
    ] {
        let sp = generate_sp_metadata(&raw_sp_metadata_config(&entity_id));
        let idp = generate_idp_metadata(&raw_idp_metadata_config(&entity_id));

        assert!(matches!(sp, Err(SamlError::Invalid(_))), "{entity_id}");
        assert!(matches!(idp, Err(SamlError::Invalid(_))), "{entity_id}");
    }
    let longest = format!("https://sp.example.com/{}", "a".repeat(1001));
    let sp = generate_sp_metadata(&raw_sp_metadata_config(&longest))?;
    assert!(sp.contains(&format!("entityID=\"{longest}\"")));
    Ok(())
}

fn raw_sp_metadata_config(entity_id: &str) -> SpMetadataInput {
    SpMetadataInput {
        entity_id: entity_id.into(),
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, SP_ACS)],
        ..SpMetadataInput::default()
    }
}

fn raw_idp_metadata_config(entity_id: &str) -> IdpMetadataInput {
    IdpMetadataInput {
        entity_id: entity_id.into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Post, IDP_SSO_POST)],
        ..IdpMetadataInput::default()
    }
}

#[test]
fn service_provider_does_not_request_a_name_id_format_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp()?;
    for format in INVALID_FORMATS {
        let mut raw_sp = sp()?.engine().clone();
        raw_sp.setting.name_id_format = vec![format.to_string()];
        expect_name_id_format_error(raw_sp.create_login_request(
            idp.engine(),
            Binding::Post,
            &LoginRequestOptions::default(),
        ))?;
    }
    Ok(())
}

#[test]
fn service_provider_without_a_name_id_format_omits_the_name_id_policy_format(
) -> Result<(), Box<dyn std::error::Error>> {
    // An omitted NameIDPolicy Format leaves the identity provider free to
    // return any kind of identifier (SAML Core §3.4.1.1).
    let idp = idp()?;
    let mut raw_sp = sp()?.engine().clone();
    raw_sp.setting.name_id_format = Vec::new();
    let context = raw_sp.create_login_request(
        idp.engine(),
        Binding::Post,
        &LoginRequestOptions::default(),
    )?;
    let xml = String::from_utf8(STANDARD.decode(&context.context)?)?;
    let policy = xml
        .split("<samlp:NameIDPolicy")
        .nth(1)
        .and_then(|rest| rest.split("/>").next())
        .ok_or("missing NameIDPolicy")?;
    assert_eq!(policy, " AllowCreate=\"true\"");
    Ok(())
}

#[test]
fn service_provider_accepts_a_name_id_format_that_is_not_an_absolute_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    // SAML Core §1.3.2 binds the writer of the value. No receiver rule rejects it.
    for format in ["local-format", "urn:%zz"] {
        let name_id = NameId::new("subject-1").with_format(NameIdFormat::Custom(format.into()));
        let session = accept_peer_response(&name_id, "")?;
        assert_eq!(session.name_id(), &name_id);
    }
    Ok(())
}
