//! Attribute name formats, and persistent and transient name identifiers,
//! through the typed identity-provider and service-provider flows.
//!
//! SAML Core §8.2, §8.3.7 and §8.3.8, with Conformance Requirements §3.3 and
//! Approved Errata 05 E78 and E86. The producer rules bind the party that
//! generates an identifier. A receiver parses a peer's identifier and does not
//! reject it for missing one of them.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::entity::iso8601_offset;
use saml_rs::raw::{Binding, LoginResponseOptions, User};
use saml_rs::template::{replace_tags_by_value, LoginResponseAttribute, LoginResponseTemplate};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, Attribute, AttributeNameFormat, AttributeValue,
    Attributes, AudienceValidationPolicy, AuthnRequest, BrowserInput, CertificatePem, Credentials,
    EntityId, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy,
    NameId, NameIdFormat, Outbound, PrivateKeyPem, ReplayPolicy, RequestedSubjectIdentifier,
    RespondSso, Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, SsoResponse, SsoSession, StartSso, Status, Subject, TemplatePolicy,
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

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

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

fn sp() -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy {
                assertions: AssertionSignaturePolicy::RequireSigned,
                audience: AudienceValidationPolicy::Validate,
                ..SpValidationPolicy::recommended()
            })
            .build()?,
    )
}

fn idp_with(templates: TemplatePolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .templates(templates)
            .build()?,
    )
}

fn idp() -> Result<Saml<saml_rs::Idp>, SamlError> {
    idp_with(TemplatePolicy::default())
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
        IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
    ))
}

fn subject(name_id: NameId) -> Subject {
    Subject::new(name_id, Vec::new())
}

fn alice() -> Subject {
    subject(NameId::new("alice@example.com", None))
}

fn response_xml(outbound: &Outbound<SsoResponse>) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = outbound
        .post_form()?
        .fields()
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(base64_decode(encoded)?)?)
}

/// The start tag of the `<saml:Attribute>` whose `Name` is `name`.
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

struct Exchange {
    xml: String,
    session: SsoSession,
}

/// SP-initiated SSO over HTTP-POST: the identity provider answers with
/// `subject` and `options`, and the service provider accepts the response.
fn exchange(subject: Subject, options: RespondSso) -> Result<Exchange, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(&sp_descriptor, &received, subject, options)?;
    let xml = response_xml(&response)?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    Ok(Exchange { xml, session })
}

fn respond(subject: Subject, options: RespondSso) -> Result<Outbound<SsoResponse>, SamlError> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    idp.initiate_sso(&sp_descriptor, subject, options)
}

fn values(values: &[&str]) -> Vec<AttributeValue> {
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
        Attribute::with_name_format(
            "displayName",
            AttributeNameFormat::Unspecified,
            values(&["Alice Example"]),
        ),
        Attribute::with_name_format(
            MAIL_OID,
            AttributeNameFormat::Uri,
            values(&["a@example.com"]),
        ),
        Attribute::with_name_format(
            "eduPersonAffiliation",
            AttributeNameFormat::Basic,
            values(&["member", "staff"]),
        ),
        Attribute::with_name_format(
            "role",
            AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()),
            values(&["admin"]),
        ),
        Attribute::new("locale", None, values(&["en"])),
        Attribute::new("groups", None, Vec::new()),
    ]);

    let exchange = exchange(alice(), RespondSso::post().attributes(attributes))?;

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
        assert_eq!(consumed.format(), Some(&format), "{name}");
        assert_eq!(consumed.name_format(), Some(format.as_uri()), "{name}");
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
    assert_eq!(locale.format(), None);
    assert_eq!(locale.name_format(), None);
    assert_eq!(locale.values(), values(&["en"]).as_slice());
    Ok(())
}

#[test]
fn unsolicited_response_carries_attribute_name_formats_and_a_generated_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let name_id = NameId::generate_transient();
    let mail = Attribute::with_name_format(
        MAIL_OID,
        AttributeNameFormat::Uri,
        values(&["a@example.com"]),
    );

    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(name_id.clone()),
        RespondSso::post().attributes(Attributes::new(vec![mail.clone()])),
    )?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;

    assert_eq!(session.name_id(), &name_id);
    assert_eq!(session.attributes().as_slice(), [mail]);
    Ok(())
}

#[test]
fn response_without_typed_attributes_has_no_attribute_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    for options in [
        RespondSso::post(),
        RespondSso::post().attributes(Attributes::default()),
    ] {
        let exchange = exchange(alice(), options)?;
        assert!(!exchange.xml.contains("AttributeStatement"));
        assert!(exchange.session.attributes().as_slice().is_empty());
    }
    Ok(())
}

#[test]
fn identity_provider_does_not_generate_a_basic_attribute_whose_name_is_not_an_xml_name(
) -> Result<(), Box<dyn std::error::Error>> {
    for name in ["", "given name", "1stName", "a<b", "-mail"] {
        let attributes = Attributes::new(vec![Attribute::with_name_format(
            name,
            AttributeNameFormat::Basic,
            values(&["x"]),
        )]);
        match respond(alice(), RespondSso::post().attributes(attributes)) {
            Err(SamlError::Invalid(message)) if message.contains("basic") => {}
            other => {
                return Err(format!("expected basic name error for {name:?}, got {other:?}").into())
            }
        }
    }
    // The basic URI is the basic format however the caller spells it.
    for attribute in [
        Attribute::with_name_format(
            "given name",
            AttributeNameFormat::Custom(BASIC.to_string()),
            values(&["x"]),
        ),
        Attribute::new("given name", Some(BASIC.to_string()), values(&["x"])),
    ] {
        assert_eq!(attribute.format(), Some(&AttributeNameFormat::Basic));
        match respond(
            alice(),
            RespondSso::post().attributes(Attributes::new(vec![attribute])),
        ) {
            Err(SamlError::Invalid(message)) if message.contains("basic") => {}
            other => return Err(format!("expected basic name error, got {other:?}").into()),
        }
    }
    for name in ["mail", "_mail", "ns:mail", "given-name.1", "é"] {
        let attributes = Attributes::new(vec![Attribute::with_name_format(
            name,
            AttributeNameFormat::Basic,
            values(&["x"]),
        )]);
        respond(alice(), RespondSso::post().attributes(attributes))?;
    }
    // The xs:Name rule is the basic format's. Other formats carry any name.
    for format in [
        AttributeNameFormat::Unspecified,
        AttributeNameFormat::Uri,
        AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()),
    ] {
        let attributes = Attributes::new(vec![Attribute::with_name_format(
            "given name",
            format,
            values(&["x"]),
        )]);
        respond(alice(), RespondSso::post().attributes(attributes))?;
    }
    Ok(())
}

#[test]
fn typed_attributes_require_the_built_in_login_response_renderer(
) -> Result<(), Box<dyn std::error::Error>> {
    let template_attribute = LoginResponseAttribute {
        name: "mail".to_string(),
        name_format: BASIC.to_string(),
        value_xsi_type: "xs:string".to_string(),
        value_tag: "mail".to_string(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    };
    for template in [
        LoginResponseTemplate {
            context: Some(saml_rs::template::LOGIN_RESPONSE_TEMPLATE.to_string()),
            attributes: Vec::new(),
        },
        LoginResponseTemplate {
            context: None,
            attributes: vec![template_attribute],
        },
    ] {
        let sp = sp()?;
        let idp = idp_with(TemplatePolicy {
            login_response_template: Some(template),
            ..TemplatePolicy::default()
        })?;
        let (sp_descriptor, _) = descriptors(&sp, &idp)?;
        let attributes = Attributes::new(vec![Attribute::with_name_format(
            "mail",
            AttributeNameFormat::Basic,
            values(&["a@example.com"]),
        )]);
        match idp.initiate_sso(
            &sp_descriptor,
            alice(),
            RespondSso::post().attributes(attributes),
        ) {
            Err(SamlError::Invalid(message)) if message.contains("login response template") => {}
            other => return Err(format!("expected template error, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn error_response_omits_typed_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let attributes = Attributes::new(vec![Attribute::with_name_format(
        "mail",
        AttributeNameFormat::Basic,
        values(&["a@example.com"]),
    )]);
    let response = respond(
        alice(),
        RespondSso::post()
            .attributes(attributes)
            .status(Status::responder()),
    )?;
    let xml = response_xml(&response)?;
    assert!(!xml.contains("Attribute"), "{xml}");
    assert!(!xml.contains("a@example.com"), "{xml}");
    Ok(())
}

/// A peer identity provider that ignores the producer rules: the raw
/// samlify-port renderer writes each `(Name, NameFormat, value)` as given.
fn accept_peer_attributes(
    attributes: &[(&str, &str, &str)],
) -> Result<SsoSession, Box<dyn std::error::Error>> {
    let template = LoginResponseTemplate {
        context: None,
        attributes: attributes
            .iter()
            .enumerate()
            .map(|(index, (name, name_format, _))| LoginResponseAttribute {
                name: (*name).to_string(),
                name_format: (*name_format).to_string(),
                value_xsi_type: "xs:string".to_string(),
                value_tag: format!("value{index}"),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            })
            .collect(),
    };
    let sp = sp()?;
    let idp = idp_with(TemplatePolicy {
        login_response_template: Some(template),
        ..TemplatePolicy::default()
    })?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let user = User {
        name_id: "alice@example.com".to_string(),
        attributes: attributes
            .iter()
            .enumerate()
            .map(|(index, (_, _, value))| (format!("value{index}"), (*value).to_string()))
            .collect(),
        session_index: None,
    };
    let context = idp.raw_identity_provider().create_login_response(
        sp.raw_service_provider(),
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some(started.pending.request_id().as_str()),
            ..LoginResponseOptions::default()
        },
    )?;
    Ok(sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(vec![FormField::new("SAMLResponse", context.context)]),
        validation(),
    )?)
}

#[test]
fn service_provider_accepts_a_basic_attribute_whose_name_is_not_an_xml_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attributes(&[("given name", BASIC, "Alice")])?;
    let given_name = attribute(&session, "given name")?;
    assert_eq!(given_name.format(), Some(&AttributeNameFormat::Basic));
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
            Attribute::with_name_format(
                "uid",
                AttributeNameFormat::Unspecified,
                values(&["alice"])
            ),
            Attribute::with_name_format(
                MAIL_OID,
                AttributeNameFormat::Uri,
                values(&["a@example.com"])
            ),
            Attribute::with_name_format(
                "eduPersonAffiliation",
                AttributeNameFormat::Basic,
                values(&["member", "staff"])
            ),
            Attribute::with_name_format(
                "role",
                AttributeNameFormat::Custom(DEPLOYMENT_FORMAT.to_string()),
                values(&["admin"])
            ),
        ]
    );
    Ok(())
}

#[test]
fn service_provider_keeps_one_attribute_for_each_name() -> Result<(), Box<dyn std::error::Error>> {
    // Values are grouped by `Name` alone, as before `NameFormat` was read. The
    // attribute reports the `NameFormat` of the first element with that name.
    let session = accept_peer_attributes(&[("role", URI, "admin"), ("role", BASIC, "auditor")])?;

    assert_eq!(
        session.attributes().as_slice(),
        [Attribute::with_name_format(
            "role",
            AttributeNameFormat::Uri,
            values(&["admin", "auditor"])
        )]
    );
    Ok(())
}

fn assert_opaque_identifier(value: &str) {
    // 160 random bits, hex encoded after an underscore: an xs:ID.
    assert_eq!(value.len(), 41, "{value}");
    assert!(value.starts_with('_'), "{value}");
    assert!(
        value[1..]
            .chars()
            .all(|character| character.is_ascii_hexdigit()),
        "{value}"
    );
    assert!(value.chars().count() <= 256);
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

        let exchange = exchange(subject(name_id.clone()), RespondSso::post())?;
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
        subject(NameId::persistent(stored.clone())?),
        RespondSso::post(),
    )?;
    let second = exchange(
        subject(NameId::persistent(stored.clone())?),
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
fn stored_persistent_identifier_is_at_most_256_characters() -> Result<(), Box<dyn std::error::Error>>
{
    // The limit counts characters, not bytes.
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
    // The limit counts characters, not bytes.
    for format in [NameIdFormat::Persistent, NameIdFormat::Transient] {
        let longest = NameId::new("é".repeat(256), Some(format.clone()));
        let exchange = exchange(subject(longest.clone()), RespondSso::post())?;
        assert_eq!(exchange.session.name_id(), &longest);

        let too_long = NameId::new("é".repeat(257), Some(format));
        expect_name_id_length_error(respond(subject(too_long), RespondSso::post()))?;
    }

    // A NameID without a format is issued in the first configured format.
    let sp = sp()?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::recommended())
            .name_id_format(NameIdFormat::Persistent)
            .build()?,
    )?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let unformatted = NameId::new("x".repeat(257), None);
    expect_name_id_length_error(idp.initiate_sso(
        &sp_descriptor,
        subject(unformatted),
        RespondSso::post(),
    ))?;

    // The rule applies to these two formats only.
    let email = NameId::new(
        format!("{}@example.com", "x".repeat(300)),
        Some(NameIdFormat::EmailAddress),
    );
    let exchange = exchange(subject(email.clone()), RespondSso::post())?;
    assert_eq!(exchange.session.name_id(), &email);
    Ok(())
}

/// A peer identity provider that ignores the producer rules: the raw renderer
/// callback writes the `<NameID>` as given.
fn accept_peer_name_id(name_id: &NameId) -> Result<SsoSession, Box<dyn std::error::Error>> {
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
    let fill = |template: &str| {
        let id = "_peer-response".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let xml = replace_tags_by_value(
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
        (id, xml)
    };
    let context = idp.raw_identity_provider().create_login_response(
        sp.raw_service_provider(),
        Binding::Post,
        &User::new(name_id.value()),
        &LoginResponseOptions {
            in_response_to: Some(&request_id),
            custom: Some(&fill as &dyn Fn(&str) -> (String, String)),
            ..LoginResponseOptions::default()
        },
    )?;
    Ok(sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(vec![FormField::new("SAMLResponse", context.context)]),
        validation(),
    )?)
}

#[test]
fn service_provider_accepts_persistent_and_transient_identifiers_that_miss_the_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    // Longer than 256 characters, and a discernible username.
    let value = format!("alice@example.com/{}", "x".repeat(300));
    for format in [NameIdFormat::Persistent, NameIdFormat::Transient] {
        let name_id = NameId::new(value.clone(), Some(format));
        let session = accept_peer_name_id(&name_id)?;
        assert_eq!(session.name_id(), &name_id);
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
        let xml = String::from_utf8(base64_decode(&started.outbound.raw_context().context)?)?;
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
            BrowserInput::<AuthnRequest>::post(vec![FormField::new(
                "SAMLRequest",
                base64_encode(xml.as_bytes()),
            )]),
            validation(),
        )?;
        let requested = received
            .message()
            .requested_subject()
            .ok_or("missing requested subject")?;
        assert_eq!(
            requested.identifier(),
            &RequestedSubjectIdentifier::NameId(NameId::new(value.clone(), Some(format)))
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
    ] {
        assert_eq!(format.as_uri(), uri);
        let name_id = NameId::new("subject-1", Some(format));
        let exchange = exchange(subject(name_id.clone()), RespondSso::post())?;
        assert!(
            name_id_element(&exchange.xml)?.contains(&format!("Format=\"{uri}\"")),
            "{uri}"
        );
        assert_eq!(exchange.session.name_id(), &name_id);
    }
    Ok(())
}
