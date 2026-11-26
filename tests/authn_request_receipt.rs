//! Identity-provider receipt of `ForceAuthn`, `Is passive`, `Subject`,
//! `NameIDPolicy`, and `RequestedAuthnContext`.
//!
//! SAML Core §3.4.1. These fields are exposed to the identity provider
//! application. Their presence does not reject the request.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::namespace::ASSERTION;
use saml_rs::constants::status_code::INVALID_NAME_ID_POLICY;
use saml_rs::{
    AcsEndpoint, AuthnContextComparison, AuthnContextReference, AuthnRequest,
    AuthnRequestRefusalReason, EntityId, ForceAuthn, FormField, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, IsPassive, MetadataTrustPolicy, NameId,
    NameIdCreationRequest, NameIdFormat, NameIdPolicy, Outbound, OutboundDelivery, Received,
    ReplayPolicy, RequestedSubject, RequestedSubjectIdentifier, RespondSso, SamlError,
    SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoAssertion, SsoEndpoint, SsoOutcome, SsoResponseBinding, StartSso, Status,
    SubordinateStatusCode,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const PERSISTENT_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const UNSPECIFIED_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
const ENCRYPTED_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const HOLDER_OF_KEY: &str = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
const SMARTCARD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
const PASSWORD_PROTECTED_TRANSPORT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const AFFILIATION: &str = "https://affiliation.example.com";
const DECLARATION: &str = "https://idp.example.com/authn-context/hardware-token";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp() -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(signing_credentials())
        .name_id_format(NameIdFormat::Unspecified)
        .validation(SpValidationPolicy::default())
        .build()?,
    ))
}

fn idp(validation_policy: IdpValidationPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(validation_policy)
        .build()?,
    ))
}

struct Receipt {
    idp: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    received: Received<AuthnRequest>,
}

fn receive(
    validation_policy: IdpValidationPolicy,
    start: StartSso,
    edit: impl FnOnce(String) -> Result<String, Box<dyn std::error::Error>>,
) -> Result<Receipt, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp(validation_policy)?;
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
    let started = sp.start_sso(&idp_descriptor, start)?;
    let xml = edit(authn_request_xml(&started.outbound)?)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(xml.as_bytes()),
        )]),
        validation(),
    )?;
    Ok(Receipt {
        idp,
        sp_descriptor,
        received,
    })
}

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.delivery() {
        OutboundDelivery::PostForm(form) => Ok(String::from_utf8(
            STANDARD.decode(form.value("SAMLRequest").ok_or("missing SAMLRequest")?)?,
        )?),
        _ => Err("expected an HTTP-POST AuthnRequest".into()),
    }
}

fn insert_root_attribute(
    mut xml: String,
    name: &str,
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let needle = "<samlp:AuthnRequest ";
    let position = xml.find(needle).ok_or("missing AuthnRequest start tag")?;
    let insert_at = position + needle.len();
    xml.insert_str(insert_at, &format!("{name}=\"{value}\" "));
    Ok(xml)
}

fn insert_before_name_id_policy(
    mut xml: String,
    element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let needle = "<samlp:NameIDPolicy";
    let position = xml.find(needle).ok_or("missing NameIDPolicy")?;
    xml.insert_str(position, element);
    Ok(xml)
}

fn insert_after_name_id_policy(
    mut xml: String,
    element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    let end = position + xml[position..].find("/>").ok_or("unclosed NameIDPolicy")? + 2;
    xml.insert_str(end, element);
    Ok(xml)
}

fn replace_name_id_policy(
    mut xml: String,
    element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    let end = position + xml[position..].find("/>").ok_or("unclosed NameIDPolicy")? + 2;
    xml.replace_range(position..end, element);
    Ok(xml)
}

fn requested_authn_context(comparison: &str, references: &str) -> String {
    format!("<samlp:RequestedAuthnContext{comparison}>{references}</samlp:RequestedAuthnContext>")
}

fn class_ref(uri: &str) -> String {
    format!("<saml:AuthnContextClassRef>{uri}</saml:AuthnContextClassRef>")
}

fn response_xml(
    response: &Outbound<saml_rs::SsoResponse>,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(
        STANDARD.decode(
            response
                .post_form()?
                .value("SAMLResponse")
                .ok_or("missing SAMLResponse")?,
        )?,
    )?)
}

/// The refusal reason of `received` and the text of its content error.
fn content_refusal(
    received: Result<Receipt, Box<dyn std::error::Error>>,
) -> Result<(AuthnRequestRefusalReason, String), Box<dyn std::error::Error>> {
    let Err(error) = received else {
        return Err("expected refusal data, got a request".into());
    };
    match *error.downcast::<SamlError>()? {
        SamlError::AuthnRequestRefused { refusal, .. } => Ok((
            refusal.reason(),
            refusal
                .content_error()
                .ok_or("refusal without a content error")?
                .to_string(),
        )),
        other => Err(format!("expected refusal data, got {other}").into()),
    }
}

#[test]
fn received_authn_request_exposes_force_authn_when_set_and_leaves_it_absent_when_omitted(
) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = receive(IdpValidationPolicy::default(), StartSso::post(), Ok)?;
    assert_eq!(omitted.received.message().force_authn(), None);

    let required = receive(
        IdpValidationPolicy::default(),
        StartSso::post().force_authn(ForceAuthn::Required),
        Ok,
    )?;
    assert_eq!(
        required.received.message().force_authn(),
        Some(ForceAuthn::Required)
    );

    let not_required = receive(
        IdpValidationPolicy::default(),
        StartSso::post().force_authn(ForceAuthn::NotRequired),
        Ok,
    )?;
    assert_eq!(
        not_required.received.message().force_authn(),
        Some(ForceAuthn::NotRequired)
    );

    let numeric_true = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_root_attribute(xml, "ForceAuthn", "1")
    })?;
    assert_eq!(
        numeric_true.received.message().force_authn(),
        Some(ForceAuthn::Required)
    );

    let numeric_false = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_root_attribute(xml, "ForceAuthn", "0")
    })?;
    assert_eq!(
        numeric_false.received.message().force_authn(),
        Some(ForceAuthn::NotRequired)
    );
    Ok(())
}

#[test]
fn received_authn_request_exposes_is_passive_when_set_and_leaves_it_absent_when_omitted(
) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = receive(IdpValidationPolicy::default(), StartSso::post(), Ok)?;
    assert_eq!(omitted.received.message().passive(), None);

    let required = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_root_attribute(xml, "IsPassive", "true")
    })?;
    assert_eq!(
        required.received.message().passive(),
        Some(IsPassive::Required)
    );

    let not_required = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_root_attribute(xml, "IsPassive", "false")
    })?;
    assert_eq!(
        not_required.received.message().passive(),
        Some(IsPassive::NotRequired)
    );

    let numeric = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_root_attribute(xml, "IsPassive", "0")
    })?;
    assert_eq!(
        numeric.received.message().passive(),
        Some(IsPassive::NotRequired)
    );
    Ok(())
}

#[test]
fn received_authn_request_exposes_requested_name_id_and_confirmation(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
            xml,
            concat!(
                "<saml:Subject>",
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" ",
                "NameQualifier=\"https://idp.example.com\" ",
                "SPNameQualifier=\"https://sp.example.com/metadata\" ",
                "SPProvidedID=\"provided-alice\">alice@example.com</saml:NameID>",
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>",
                "</saml:Subject>"
            ),
        )
    })?;
    let subject = receipt
        .received
        .message()
        .requested_subject()
        .ok_or("missing requested subject")?;
    let RequestedSubjectIdentifier::NameId(name_id) = subject.identifier() else {
        return Err("expected a NameID identifier".into());
    };
    assert_eq!(name_id.value(), "alice@example.com");
    assert_eq!(name_id.format(), Some(&NameIdFormat::EmailAddress));
    assert_eq!(
        name_id.format().map(NameIdFormat::as_uri),
        Some(EMAIL_FORMAT)
    );
    assert_eq!(name_id.name_qualifier(), Some("https://idp.example.com"));
    assert_eq!(
        name_id.sp_name_qualifier(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(name_id.sp_provided_id(), Some("provided-alice"));
    assert_eq!(
        subject.name_id().map(NameId::value),
        Some("alice@example.com")
    );
    let confirmation = subject
        .confirmations()
        .first()
        .ok_or("missing confirmation")?;
    assert!(confirmation.raw_xml().contains(BEARER));
    Ok(())
}

#[test]
fn received_authn_request_reads_name_id_formats_by_their_schema_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        let xml = insert_before_name_id_policy(
            xml,
            &format!(
                "<saml:Subject><saml:NameID Format=\"&#xA; {PERSISTENT_FORMAT}&#x9;\">alice</saml:NameID></saml:Subject>"
            ),
        )?;
        replace_name_id_policy(
            xml,
            &format!(
                "<samlp:NameIDPolicy Format=\"&#x9;{PERSISTENT_FORMAT}  \" AllowCreate=\"true\"/>"
            ),
        )
    })?;
    let message = receipt.received.message();
    assert_eq!(
        message
            .requested_subject()
            .and_then(RequestedSubject::name_id),
        Some(&NameId::new("alice").with_format(NameIdFormat::Persistent))
    );
    assert_eq!(
        message.name_id_policy().and_then(NameIdPolicy::format),
        Some(&NameIdFormat::Persistent)
    );
    Ok(())
}

#[test]
fn received_authn_request_without_subject_leaves_it_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), Ok)?;
    assert_eq!(receipt.received.message().requested_subject(), None);
    Ok(())
}

#[test]
fn received_authn_request_without_identifier_presumes_the_presenter(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/></saml:Subject>",
        )
    })?;
    let subject = receipt
        .received
        .message()
        .requested_subject()
        .ok_or("missing requested subject")?;
    assert!(matches!(
        subject.identifier(),
        RequestedSubjectIdentifier::NoIdentifier
    ));
    assert_eq!(subject.name_id(), None);
    assert_eq!(subject.confirmations().len(), 1);
    Ok(())
}

#[test]
fn received_authn_request_keeps_base_id_and_encrypted_id_distinct_from_the_presenter(
) -> Result<(), Box<dyn std::error::Error>> {
    let base_id = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:BaseID>opaque</saml:BaseID></saml:Subject>",
        )
    })?;
    assert!(matches!(
        base_id
            .received
            .message()
            .requested_subject()
            .map(RequestedSubject::identifier),
        Some(RequestedSubjectIdentifier::BaseId)
    ));

    let encrypted = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:EncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID></saml:Subject>",
        )
    })?;
    assert!(matches!(
        encrypted
            .received
            .message()
            .requested_subject()
            .map(RequestedSubject::identifier),
        Some(RequestedSubjectIdentifier::EncryptedId)
    ));
    Ok(())
}

#[test]
fn unsigned_authn_request_fields_are_accepted_under_default_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        let xml = insert_root_attribute(xml, "ForceAuthn", "true")?;
        let xml = insert_root_attribute(xml, "IsPassive", "true")?;
        insert_before_name_id_policy(
            xml,
            "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
        )
    })?;
    let message = receipt.received.message();
    assert_eq!(message.force_authn(), Some(ForceAuthn::Required));
    assert_eq!(message.passive(), Some(IsPassive::Required));
    assert_eq!(
        message
            .requested_subject()
            .and_then(RequestedSubject::name_id)
            .map(NameId::value),
        Some("alice@example.com")
    );

    let response = receipt.idp.respond_sso(
        &receipt.sp_descriptor,
        &receipt.received,
        SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now()),
        RespondSso::post(),
    )?;
    assert!(response.post_form()?.value("SAMLResponse").is_some());
    Ok(())
}

#[test]
fn received_authn_request_refuses_a_non_boolean_flag_or_a_non_integer_index(
) -> Result<(), Box<dyn std::error::Error>> {
    for (attribute, value, expected) in [
        ("ForceAuthn", "maybe", "ForceAuthn"),
        ("IsPassive", "TRUE", "IsPassive"),
        ("ForceAuthn", "\u{a0}true", "ForceAuthn"),
        (
            "AssertionConsumerServiceIndex",
            " 1 0 ",
            "assertionConsumerServiceIndex",
        ),
    ] {
        let (reason, error) = content_refusal(receive(
            IdpValidationPolicy::default(),
            StartSso::post(),
            |xml| insert_root_attribute(xml, attribute, value),
        ))?;
        assert_eq!(
            reason,
            AuthnRequestRefusalReason::MalformedRequest,
            "{value}"
        );
        assert!(error.contains(expected), "{value}: {error}");
    }
    Ok(())
}

#[test]
fn received_authn_request_collapses_xml_schema_whitespace_in_booleans_and_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        let xml = insert_root_attribute(xml, "ForceAuthn", " true ")?;
        let xml = insert_root_attribute(xml, "IsPassive", "&#9;0&#10;")?;
        let acs_url = format!(" AssertionConsumerServiceURL=\"{SP_ACS}\"");
        if !xml.contains(&acs_url) {
            return Err("missing AssertionConsumerServiceURL".into());
        }
        let xml = insert_root_attribute(
            xml.replacen(&acs_url, "", 1),
            "AssertionConsumerServiceIndex",
            " 0 ",
        )?;
        if !xml.contains("AllowCreate=\"true\"") {
            return Err("missing AllowCreate".into());
        }
        Ok(xml.replace("AllowCreate=\"true\"", "AllowCreate=\"&#13; false \""))
    })?;
    let message = receipt.received.message();
    assert_eq!(message.force_authn(), Some(ForceAuthn::Required));
    assert_eq!(message.passive(), Some(IsPassive::NotRequired));
    assert_eq!(message.acs_index(), Some(0));
    assert_eq!(
        message.name_id_policy().map(NameIdPolicy::creation_request),
        Some(NameIdCreationRequest::DoNotAllowCreate)
    );
    Ok(())
}

#[test]
fn received_authn_request_collapses_protocol_binding_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    const UNKNOWN: &str = "urn:example:unsupported-binding";
    let receive_with_binding = |binding: &str| {
        receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
            let attribute = format!("ProtocolBinding=\"{POST}\"");
            if !xml.contains(&attribute) {
                return Err("missing HTTP-POST ProtocolBinding".into());
            }
            Ok(xml.replacen(&attribute, &format!("ProtocolBinding=\"{binding}\""), 1))
        })
    };

    let canonical = receive_with_binding(POST)?;
    assert_eq!(
        canonical.received.message().protocol_binding(),
        Some(SsoResponseBinding::Post)
    );

    let (reason, error) = content_refusal(receive_with_binding(UNKNOWN))?;
    assert_eq!(
        reason,
        AuthnRequestRefusalReason::UnsupportedProtocolBinding
    );
    assert!(error.ends_with(&format!(
        "unsupported AuthnRequest ProtocolBinding {UNKNOWN}"
    )));

    let padded = receive_with_binding(&format!(" &#x9;{POST}&#xD;&#xA; "))?;
    assert_eq!(
        padded.received.message().protocol_binding(),
        Some(SsoResponseBinding::Post)
    );
    Ok(())
}

#[test]
fn received_authn_request_refuses_two_identifiers_or_two_subjects(
) -> Result<(), Box<dyn std::error::Error>> {
    for (subject, expected) in [
        (
            "<saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:EncryptedID/></saml:Subject>",
            "one identifier",
        ),
        (
            concat!(
                "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
                "<saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject>"
            ),
            "Subject must occur once",
        ),
    ] {
        let (reason, error) = content_refusal(receive(
            IdpValidationPolicy::default(),
            StartSso::post(),
            |xml| insert_before_name_id_policy(xml, subject),
        ))?;
        assert_eq!(reason, AuthnRequestRefusalReason::MalformedRequest, "{expected}");
        assert!(error.contains(expected), "{expected}: {error}");
    }
    Ok(())
}

#[test]
fn received_authn_request_with_two_name_id_policies_is_refused_for_a_requester_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp(IdpValidationPolicy::default())?;
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
    let request_id = started.pending.request_id().as_str();
    let original = authn_request_xml(&started.outbound)?;

    for second in [
        format!(r#"<samlp:NameIDPolicy Format="{EMAIL_FORMAT}"/>"#),
        "<samlp:NameIDPolicy/>".to_string(),
    ] {
        let xml = insert_before_name_id_policy(original.clone(), &second)?;
        let received = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(vec![FormField::new(
                "SAMLRequest",
                STANDARD.encode(xml.as_bytes()),
            )]),
            validation(),
        );
        let Err(SamlError::AuthnRequestRefused { refusal, .. }) = received else {
            return Err(format!("{second}: expected a refusal, got {received:?}").into());
        };
        assert_eq!(
            refusal.reason(),
            AuthnRequestRefusalReason::RepeatedNameIdPolicy
        );
        let response = response_xml(&idp.respond_sso_refusal(
            &sp_descriptor,
            &refusal,
            RespondSso::post(),
        )?)?;
        assert!(response.contains(&format!(r#"InResponseTo="{request_id}""#)));
        assert!(response.contains(saml_rs::constants::status_code::REQUESTER));
        assert!(!response.contains("<saml:Assertion"));
    }
    Ok(())
}

#[test]
fn received_authn_request_rejects_qualified_name_id_qualifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    for attribute in ["NameQualifier", "SPNameQualifier", "SPProvidedID"] {
        let prefixed_only = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
            insert_before_name_id_policy(
                    xml,
                    &format!(
                        "<saml:Subject><saml:NameID xmlns:x=\"urn:example:foreign\" x:{attribute}=\"https://evil.example\">alice@example.com</saml:NameID></saml:Subject>"
                    ),
                )
        });
        let Err(error) = prefixed_only else {
            return Err(format!("qualified {attribute} was accepted").into());
        };
        let message = error.to_string();
        if !message.contains(attribute) || !message.contains("unqualified") {
            return Err(format!("qualified {attribute} produced {message}").into());
        }
    }

    let both_forms = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
                xml,
                concat!(
                    "<saml:Subject><saml:NameID xmlns:x=\"urn:example:foreign\" ",
                    "NameQualifier=\"https://idp.example.com\" ",
                    "x:NameQualifier=\"https://evil.example\">alice@example.com</saml:NameID></saml:Subject>"
                ),
            )
    });
    assert!(matches!(
        both_forms,
        Err(error) if error.to_string().contains("NameQualifier")
            && error.to_string().contains("unqualified")
    ));
    Ok(())
}

#[test]
fn received_authn_request_keeps_the_name_id_policy_sp_name_qualifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let qualifier_only = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        replace_name_id_policy(
            xml,
            &format!("<samlp:NameIDPolicy SPNameQualifier=\"{AFFILIATION}\"/>"),
        )
    })?;
    let policy = qualifier_only
        .received
        .message()
        .name_id_policy()
        .ok_or("missing NameIDPolicy")?;
    assert_eq!(
        (
            policy.format(),
            policy.sp_name_qualifier(),
            policy.creation_request()
        ),
        (None, Some(AFFILIATION), NameIdCreationRequest::Unspecified)
    );

    let every_attribute = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        replace_name_id_policy(
                xml,
                &format!(
                    "<samlp:NameIDPolicy Format=\"{EMAIL_FORMAT}\" SPNameQualifier=\"{AFFILIATION}\" AllowCreate=\"true\"/>"
                ),
            )
    })?;
    let policy = every_attribute
        .received
        .message()
        .name_id_policy()
        .ok_or("missing NameIDPolicy")?;
    assert_eq!(
        (
            policy.format(),
            policy.sp_name_qualifier(),
            policy.creation_request()
        ),
        (
            Some(&NameIdFormat::EmailAddress),
            Some(AFFILIATION),
            NameIdCreationRequest::AllowCreate
        )
    );

    let qualified = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        replace_name_id_policy(
                xml,
                &format!(
                    "<samlp:NameIDPolicy xmlns:x=\"urn:example:foreign\" x:SPNameQualifier=\"{AFFILIATION}\"/>"
                ),
            )
    });
    assert!(matches!(
        qualified,
        Err(error) if error.to_string().contains("SPNameQualifier")
            && error.to_string().contains("unqualified")
    ));
    Ok(())
}

#[test]
fn received_authn_request_rejects_a_qualified_flag_and_a_foreign_subject() {
    let qualified = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        let needle = "<samlp:AuthnRequest ";
        let position = xml.find(needle).ok_or("missing AuthnRequest start tag")?;
        let insert_at = position + needle.len();
        Ok(format!(
            "{}xmlns:x=\"urn:example:foreign\" x:ForceAuthn=\"true\" {}",
            &xml[..insert_at],
            &xml[insert_at..]
        ))
    });
    assert!(matches!(
        qualified,
        Err(error) if error.to_string().contains("ForceAuthn")
            && error.to_string().contains("unqualified")
    ));

    let foreign_subject = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
                xml,
                "<x:Subject xmlns:x=\"urn:example:foreign\"><x:NameID>alice@example.com</x:NameID></x:Subject>",
            )
    });
    assert!(matches!(
        foreign_subject,
        Err(error) if error.to_string().contains("Subject")
            && error.to_string().contains("namespace")
    ));

    let foreign_identifier = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_before_name_id_policy(
            xml,
            "<saml:Subject><x:EncryptedID xmlns:x=\"urn:example:foreign\"/></saml:Subject>",
        )
    });
    assert!(matches!(
        foreign_identifier,
        Err(error) if error.to_string().contains("EncryptedID")
            && error.to_string().contains("namespace")
    ));
}

#[test]
fn received_authn_request_exposes_the_requested_authn_context_in_request_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = receive(IdpValidationPolicy::default(), StartSso::post(), Ok)?;
    assert_eq!(omitted.received.message().requested_authn_context(), None);

    let classes = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_after_name_id_policy(
            xml,
            &requested_authn_context(
                "",
                &format!(
                    "{}{}",
                    class_ref(&format!("\n  {SMARTCARD} ")),
                    class_ref(PASSWORD_PROTECTED_TRANSPORT)
                ),
            ),
        )
    })?;
    let requested = classes
        .received
        .message()
        .requested_authn_context()
        .ok_or("missing RequestedAuthnContext")?;
    assert_eq!(requested.comparison(), AuthnContextComparison::Exact);
    assert_eq!(
        requested.references(),
        [
            AuthnContextReference::class(SMARTCARD)?,
            AuthnContextReference::class(PASSWORD_PROTECTED_TRANSPORT)?,
        ]
    );

    let declarations = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_after_name_id_policy(
            xml,
            &requested_authn_context(
                " Comparison=\"minimum\"",
                &format!("<saml:AuthnContextDeclRef>{DECLARATION}</saml:AuthnContextDeclRef>"),
            ),
        )
    })?;
    let requested = declarations
        .received
        .message()
        .requested_authn_context()
        .ok_or("missing RequestedAuthnContext")?;
    assert_eq!(requested.comparison(), AuthnContextComparison::Minimum);
    assert_eq!(
        requested.references(),
        [AuthnContextReference::declaration(DECLARATION)?]
    );
    Ok(())
}

#[test]
fn received_authn_request_refuses_a_requested_authn_context_outside_its_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let refused = [
        (
            requested_authn_context(" Comparison=\"Exact\"", &class_ref(SMARTCARD)),
            "Comparison",
        ),
        (requested_authn_context("", ""), "must contain"),
        (
            requested_authn_context(
                "",
                &format!(
                    "{}<saml:AuthnContextDeclRef>{DECLARATION}</saml:AuthnContextDeclRef>",
                    class_ref(SMARTCARD)
                ),
            ),
            "must not mix",
        ),
        (
            format!("{0}{0}", requested_authn_context("", &class_ref(SMARTCARD))),
            "must occur once",
        ),
    ];
    for (element, expected) in refused {
        let (reason, error) = content_refusal(receive(
            IdpValidationPolicy::default(),
            StartSso::post(),
            |xml| insert_after_name_id_policy(xml, &element),
        ))?;
        assert_eq!(
            reason,
            AuthnRequestRefusalReason::MalformedRequest,
            "{element}"
        );
        assert!(error.contains(expected), "{element} produced {error}");
    }

    let rejected_before_the_signature_check = [
        (
            requested_authn_context(
                " xmlns:x=\"urn:example:foreign\" x:Comparison=\"minimum\"",
                &class_ref(SMARTCARD),
            ),
            "unqualified",
        ),
        (
            requested_authn_context(
                "",
                "<x:AuthnContextDeclRef xmlns:x=\"urn:example:foreign\">urn:example:decl</x:AuthnContextDeclRef>",
            ),
            "namespace",
        ),
    ];
    for (element, expected) in rejected_before_the_signature_check {
        let received = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
            insert_after_name_id_policy(xml, &element)
        });
        let Err(error) = received else {
            return Err(format!("{element} was accepted").into());
        };
        assert!(
            matches!(
                error.downcast_ref::<SamlError>(),
                Some(SamlError::ProtocolProfile(message)) if message.contains(expected)
            ),
            "{element} produced {error}"
        );
    }
    Ok(())
}

#[test]
fn respond_sso_writes_the_stated_authn_context_and_refuses_an_unmet_exact_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_after_name_id_policy(xml, &requested_authn_context("", &class_ref(SMARTCARD)))
    })?;
    let assertion = || SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now());
    let respond = |outcome: SsoOutcome| {
        receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            outcome,
            RespondSso::post(),
        )
    };

    let unspecified = respond(assertion().into());
    assert!(
        matches!(unspecified, Err(SamlError::Invalid(message)) if message.contains(UNSPECIFIED))
    );
    let other_class = respond(
        assertion()
            .authn_context(AuthnContextReference::class(PASSWORD_PROTECTED_TRANSPORT)?)
            .into(),
    );
    assert!(
        matches!(other_class, Err(SamlError::Invalid(message)) if message.contains(PASSWORD_PROTECTED_TRANSPORT))
    );
    let declaration_with_the_class_uri = respond(
        assertion()
            .authn_context(AuthnContextReference::declaration(SMARTCARD)?)
            .into(),
    );
    assert!(matches!(
        declaration_with_the_class_uri,
        Err(SamlError::Invalid(_))
    ));

    let met = response_xml(&respond(
        assertion()
            .authn_context(AuthnContextReference::class(SMARTCARD)?)
            .into(),
    )?)?;
    assert!(met.contains(&format!(
        "<saml:AuthnContext><saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef></saml:AuthnContext>"
    )));

    let refused = response_xml(&respond(SsoOutcome::Failure(
        Status::responder().with_subordinate(SubordinateStatusCode::no_authn_context()),
    ))?)?;
    assert!(refused.contains(
        "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\"><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext\"/></samlp:StatusCode>"
    ));
    assert!(!refused.contains("Assertion"));

    Ok(())
}

#[test]
fn respond_sso_leaves_a_comparison_other_than_exact_to_the_caller(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        insert_after_name_id_policy(
            xml,
            &requested_authn_context(
                " Comparison=\"minimum\"",
                &class_ref(PASSWORD_PROTECTED_TRANSPORT),
            ),
        )
    })?;
    let response = response_xml(
        &receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now())
                .authn_context(AuthnContextReference::declaration(DECLARATION)?),
            RespondSso::post(),
        )?,
    )?;
    assert!(response.contains(&format!(
        "<saml:AuthnContext><saml:AuthnContextDeclRef>{DECLARATION}</saml:AuthnContextDeclRef></saml:AuthnContext>"
    )));
    Ok(())
}

#[test]
fn respond_sso_writes_the_context_when_the_request_specifies_none(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), Ok)?;
    let response = receipt.idp.respond_sso(
        &receipt.sp_descriptor,
        &receipt.received,
        SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now())
            .authn_context(AuthnContextReference::class(SMARTCARD)?),
        RespondSso::post(),
    )?;
    assert!(response_xml(&response)?.contains(&format!(
        "<saml:AuthnContextClassRef>{SMARTCARD}</saml:AuthnContextClassRef>"
    )));
    Ok(())
}

#[test]
fn respond_sso_enforces_the_requested_name_id_format() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        replace_name_id_policy(
            xml,
            &format!("<samlp:NameIDPolicy Format=\"&#x9;{PERSISTENT_FORMAT}  \"/>"),
        )
    })?;
    let respond = |name_id| {
        receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoAssertion::new(name_id, SystemTime::now()),
            RespondSso::post(),
        )
    };

    for issued in [None, Some(NameIdFormat::EmailAddress)] {
        let name_id = NameId::new("alice@example.com");
        let name_id = match issued.clone() {
            Some(format) => name_id.with_format(format),
            None => name_id,
        };
        let refused = respond(name_id);
        assert!(matches!(
            refused,
            Err(SamlError::NameIdPolicyFormatMismatch {
                requested: NameIdFormat::Persistent,
                issued: actual,
                ..
            }) if actual == issued
        ));
    }

    let issued_format = format!(" {PERSISTENT_FORMAT} ");
    let response = respond(
        NameId::new("alice-pairwise-id").with_format(NameIdFormat::Custom(issued_format.clone())),
    )?;
    assert!(response_xml(&response)?.contains(&format!(
        "<saml:Subject><saml:NameID Format=\"{issued_format}\">alice-pairwise-id</saml:NameID>"
    )));

    let failure = receipt.idp.respond_sso(
        &receipt.sp_descriptor,
        &receipt.received,
        SsoOutcome::Failure(
            Status::responder()
                .with_subordinate(SubordinateStatusCode::try_new(INVALID_NAME_ID_POLICY)?),
        ),
        RespondSso::post(),
    )?;
    let xml = response_xml(&failure)?;
    assert!(xml.contains(INVALID_NAME_ID_POLICY), "{xml}");
    assert!(!xml.contains("<saml:Assertion"), "{xml}");
    assert!(!xml.contains("<saml:EncryptedAssertion"), "{xml}");
    Ok(())
}

#[test]
fn respond_sso_refuses_plaintext_for_an_encrypted_name_id_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
        replace_name_id_policy(
            xml,
            &format!("<samlp:NameIDPolicy Format=\" {ENCRYPTED_FORMAT} \"/>"),
        )
    })?;
    let refused = receipt.idp.respond_sso(
        &receipt.sp_descriptor,
        &receipt.received,
        SsoAssertion::new(NameId::new("alice@example.com"), SystemTime::now()),
        RespondSso::post(),
    );
    assert!(matches!(
        refused,
        Err(SamlError::NameIdPolicyRequiresEncryptedId)
    ));
    Ok(())
}

#[test]
fn respond_sso_refuses_an_identifier_outside_the_requested_sp_name_qualifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let receive_policy = |format: Option<&str>, qualifier: &str| {
        let format = format.map_or_else(String::new, |format| format!(" Format=\"{format}\""));
        receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
            replace_name_id_policy(
                xml,
                &format!("<samlp:NameIDPolicy{format} SPNameQualifier=\"{qualifier}\" AllowCreate=\"true\"/>"),
            )
        })
    };
    let persistent = |sp_name_qualifier: Option<&str>| {
        let pseudonym = NameId::generate_persistent();
        match sp_name_qualifier {
            Some(sp_name_qualifier) => pseudonym.with_sp_name_qualifier(sp_name_qualifier),
            None => pseudonym,
        }
    };
    let respond = |receipt: &Receipt, name_id: NameId| {
        receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoAssertion::new(name_id, SystemTime::now()),
            RespondSso::post(),
        )
    };

    for format in [
        PERSISTENT_FORMAT.to_string(),
        format!(" {PERSISTENT_FORMAT} "),
    ] {
        let receipt = receive_policy(Some(&format), AFFILIATION)?;
        for issued in [
            None,
            Some(SP_ENTITY_ID),
            Some(" https://affiliation.example.com"),
        ] {
            let refused = respond(&receipt, persistent(issued));
            assert!(
                matches!(&refused, Err(SamlError::Invalid(message)) if message.contains("SPNameQualifier") && message.contains(AFFILIATION)),
                "{format} {issued:?}: {refused:?}"
            );
        }
        let answered = response_xml(&respond(&receipt, persistent(Some(AFFILIATION)))?)?;
        assert!(answered.contains(&format!("SPNameQualifier=\"{AFFILIATION}\"")));

        let error = receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoOutcome::Failure(
                Status::responder()
                    .with_subordinate(SubordinateStatusCode::try_new(INVALID_NAME_ID_POLICY)?),
            ),
            RespondSso::post(),
        );
        assert!(error.is_ok(), "{error:?}");
    }

    let mut accepted_outside_affiliation = Vec::new();
    for format in [None, Some(UNSPECIFIED_FORMAT)] {
        let receipt = receive_policy(format, AFFILIATION)?;
        let answered = response_xml(&respond(&receipt, persistent(Some(AFFILIATION)))?)?;
        let document = roxmltree::Document::parse(&answered)?;
        let name_id = document
            .descendants()
            .find(|node| node.has_tag_name((ASSERTION, "NameID")))
            .ok_or("missing response NameID")?;
        assert_eq!(name_id.attribute("Format"), Some(PERSISTENT_FORMAT));
        assert_eq!(name_id.attribute("SPNameQualifier"), Some(AFFILIATION));
        for issued in [None, Some(SP_ENTITY_ID)] {
            match respond(&receipt, persistent(issued)) {
                Ok(_) => accepted_outside_affiliation.push((format, issued)),
                Err(SamlError::Invalid(message)) if message.contains("SPNameQualifier") => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    assert!(
        accepted_outside_affiliation.is_empty(),
        "issued outside the requested affiliation for (requested format, issued qualifier) {accepted_outside_affiliation:?}"
    );

    let direct = receive_policy(None, SP_ENTITY_ID)?;
    for (name_id, format) in [
        (NameId::generate_persistent(), PERSISTENT_FORMAT),
        (
            NameId::generate_transient(),
            NameIdFormat::Transient.as_uri(),
        ),
    ] {
        let answered = response_xml(&respond(&direct, name_id)?)?;
        assert!(answered.contains(&format!("<saml:NameID Format=\"{format}\">")));
    }

    let email = NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress);
    let refused = respond(&direct, email);
    assert!(
        matches!(&refused, Err(SamlError::Invalid(message)) if message.contains("SPNameQualifier")),
        "unqualified email in the direct SP namespace: {refused:?}"
    );

    let explicit = receive_policy(Some(PERSISTENT_FORMAT), SP_ENTITY_ID)?;
    let refused = respond(&explicit, persistent(None));
    assert!(
        matches!(&refused, Err(SamlError::Invalid(message)) if message.contains("SPNameQualifier")),
        "unqualified persistent ID with an explicit format and namespace: {refused:?}"
    );

    let custom = receive_policy(Some("https://sp.example.com/custom-format"), AFFILIATION)?;
    respond(&custom, persistent(None))?;
    Ok(())
}

#[test]
fn respond_sso_issues_only_the_requested_subject() -> Result<(), Box<dyn std::error::Error>> {
    let receive_subject = |subject: &str, policy: &str| {
        receive(IdpValidationPolicy::default(), StartSso::post(), |xml| {
            replace_name_id_policy(
                xml,
                &format!("<saml:Subject>{subject}</saml:Subject>{policy}"),
            )
        })
    };
    let respond = |receipt: &Receipt, name_id: NameId, options: RespondSso| {
        receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoAssertion::new(name_id, SystemTime::now()),
            options,
        )
    };
    let respond_failure = |receipt: &Receipt, status: Status| {
        receipt.idp.respond_sso(
            &receipt.sp_descriptor,
            &receipt.received,
            SsoOutcome::Failure(status),
            RespondSso::post(),
        )
    };
    let persistent = |value: &str| NameId::new(value).with_format(NameIdFormat::Persistent);
    let is_refused = |result: &Result<Outbound<saml_rs::SsoResponse>, SamlError>| matches!(result, Err(SamlError::Invalid(message)) if message.contains("requested Subject"));

    let receipt = receive_subject(
        &format!("<saml:NameID Format=\"{PERSISTENT_FORMAT}\">alice</saml:NameID>"),
        &format!("<samlp:NameIDPolicy Format=\"{EMAIL_FORMAT}\"/>"),
    )?;
    let same_format = receive_subject(
        &format!("<saml:NameID Format=\"{PERSISTENT_FORMAT}\">alice</saml:NameID>"),
        &format!("<samlp:NameIDPolicy Format=\"{PERSISTENT_FORMAT}\"/>"),
    )?;
    for issued in [
        persistent("bob"),
        NameId::new("alice")
            .with_format(NameIdFormat::Persistent)
            .with_sp_name_qualifier(SP_ENTITY_ID),
    ] {
        let refused = respond(&same_format, issued.clone(), RespondSso::post());
        assert!(is_refused(&refused), "{issued:?}: {refused:?}");
    }
    let matching_subject = respond(&same_format, persistent("alice"), RespondSso::post());
    assert!(matching_subject.is_ok(), "{matching_subject:?}");

    let refused = respond(&receipt, persistent("alice"), RespondSso::post());
    assert!(matches!(
        refused,
        Err(SamlError::NameIdPolicyFormatMismatch {
            requested: NameIdFormat::EmailAddress,
            issued: Some(NameIdFormat::Persistent),
            ..
        })
    ));
    let policy_format = respond(
        &receipt,
        NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress),
        RespondSso::post(),
    );
    assert!(response_xml(&policy_format?)?.contains(&format!(
        "<saml:Subject><saml:NameID Format=\"{EMAIL_FORMAT}\">alice@example.com</saml:NameID>"
    )));
    let error = respond_failure(
        &receipt,
        Status::responder().with_subordinate(SubordinateStatusCode::try_new(
            saml_rs::constants::status_code::UNKNOWN_PRINCIPAL,
        )?),
    );
    assert!(error.is_ok(), "{error:?}");

    let without_policy_format = receive_subject(
        &format!("<saml:NameID Format=\"{PERSISTENT_FORMAT}\">alice</saml:NameID>"),
        "<samlp:NameIDPolicy AllowCreate=\"false\"/>",
    )?;
    let other_format = respond(
        &without_policy_format,
        NameId::new("alice"),
        RespondSso::post(),
    );
    assert!(is_refused(&other_format), "{other_format:?}");

    let omitted_format = receive_subject(
        "<saml:NameID>alice</saml:NameID>",
        "<samlp:NameIDPolicy AllowCreate=\"false\"/>",
    )?;
    let unspecified = respond(
        &omitted_format,
        NameId::new("alice").with_format(NameIdFormat::Custom(UNSPECIFIED_FORMAT.to_string())),
        RespondSso::post(),
    );
    assert!(unspecified.is_ok(), "{unspecified:?}");

    for subject in [
        "<saml:BaseID>opaque</saml:BaseID>",
        "<saml:EncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID>",
    ] {
        let receipt = receive_subject(subject, "")?;
        let refused = respond(&receipt, persistent("alice"), RespondSso::post());
        assert!(is_refused(&refused), "{subject}: {refused:?}");
        let error = respond_failure(&receipt, Status::responder());
        assert!(error.is_ok(), "{subject}: {error:?}");
    }

    let holder_of_key = format!("<saml:SubjectConfirmation Method=\"{HOLDER_OF_KEY}\"/>");
    let other_recipient = format!(
        "<saml:SubjectConfirmation Method=\"{BEARER}\"><saml:SubjectConfirmationData Recipient=\"https://other.example.com/acs\"/></saml:SubjectConfirmation>"
    );
    let alice = format!("<saml:NameID Format=\"{PERSISTENT_FORMAT}\">alice</saml:NameID>");
    for subject in [
        holder_of_key.clone(),
        format!("{alice}{holder_of_key}"),
        format!("{alice}{other_recipient}"),
    ] {
        let receipt = receive_subject(&subject, "")?;
        let refused = respond(&receipt, persistent("alice"), RespondSso::post());
        assert!(is_refused(&refused), "{subject}: {refused:?}");
        let error = respond_failure(&receipt, Status::responder());
        assert!(error.is_ok(), "{subject}: {error:?}");
    }
    let either = receive_subject(
        &format!("{alice}{holder_of_key}{other_recipient}<saml:SubjectConfirmation Method=\"&#xA; {BEARER} \"/>"),
        "",
    )?;
    let bearer = respond(&either, persistent("alice"), RespondSso::post());
    assert!(bearer.is_ok(), "{bearer:?}");
    Ok(())
}

#[test]
fn authn_context_reference_requires_an_absolute_uri() {
    assert!(matches!(
        AuthnContextReference::class("Smartcard"),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        AuthnContextReference::declaration(""),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn receive_sso_rejects_a_malformed_xml_declaration() -> Result<(), Box<dyn std::error::Error>> {
    let with_declaration = |declaration: &'static str| {
        move |xml: String| -> Result<String, Box<dyn std::error::Error>> {
            let body = match xml.strip_prefix("<?xml") {
                Some(rest) => rest.split_once("?>").ok_or("unclosed declaration")?.1,
                None => xml.as_str(),
            };
            Ok(format!("{declaration}{body}"))
        }
    };
    let accepted = receive(
        IdpValidationPolicy::default(),
        StartSso::post(),
        with_declaration(r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>"#),
    )?;
    assert_eq!(accepted.received.message().issuer().as_str(), SP_ENTITY_ID);

    match receive(
        IdpValidationPolicy::default(),
        StartSso::post(),
        with_declaration(r#"<?xml version="1.0" garbage="yes"?>"#),
    ) {
        Err(error) if matches!(error.downcast_ref(), Some(SamlError::Xml { .. })) => Ok(()),
        Err(error) => Err(format!("expected an XML error, got {error}").into()),
        Ok(_) => Err("a malformed XML declaration was accepted".into()),
    }
}
