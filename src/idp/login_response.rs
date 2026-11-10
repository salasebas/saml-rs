use crate::constants::{attribute_name_format, namespace};
use crate::error::SamlError;
use crate::model::{Attribute, AuthnContextReference, AuthnContextReferenceKind, Status};
use crate::template::{write_login_response_attribute_statement, LoginResponseAttribute};
use crate::xml::any_uri::is_absolute_uri_reference;
use crate::xml::name::is_name;
use crate::xml::write::XmlWriter;
use crate::xml::OutboundNameIdQualifiers;

const VERSION: &str = "2.0";
const XMLNS_XS: &str = "http://www.w3.org/2001/XMLSchema";
const XMLNS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const BEARER_CONFIRMATION: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub(super) struct AuthnStatementXml<'a> {
    pub(super) authn_instant: &'a str,
    pub(super) session_index: Option<&'a str>,
    pub(super) authn_context: &'a AuthnContextReference,
}

pub(super) struct LoginResponseXml<'a> {
    pub(super) protocol_prefix: &'a str,
    pub(super) assertion_prefix: &'a str,
    pub(super) response_id: &'a str,
    pub(super) assertion_id: &'a str,
    pub(super) issue_instant: &'a str,
    pub(super) destination: &'a str,
    pub(super) subject_recipient: &'a str,
    pub(super) issuer: &'a str,
    pub(super) status: &'a Status,
    pub(super) subject_confirmation_not_on_or_after: &'a str,
    pub(super) conditions_not_before: &'a str,
    pub(super) conditions_not_on_or_after: &'a str,
    pub(super) audience: &'a str,
    /// `<NameID>` `Format`. `None` omits the attribute.
    pub(super) name_id_format: Option<&'a str>,
    pub(super) name_id: &'a str,
    pub(super) name_id_qualifiers: OutboundNameIdQualifiers<'a>,
    pub(super) in_response_to: Option<&'a str>,
    pub(super) authn_statement: Option<AuthnStatementXml<'a>>,
    pub(super) attributes: &'a [LoginResponseAttribute],
    pub(super) user_attributes: &'a [(String, String)],
    pub(super) typed_attributes: &'a [Attribute],
}

pub(super) fn render_default_login_response(
    input: &LoginResponseXml<'_>,
) -> Result<String, SamlError> {
    let response_name = qname(input.protocol_prefix, "Response");
    let protocol_xmlns = format!("xmlns:{}", input.protocol_prefix);
    let assertion_xmlns = format!("xmlns:{}", input.assertion_prefix);
    let assertion_name = qname(input.assertion_prefix, "Assertion");

    let mut response_attrs = vec![
        (protocol_xmlns.as_str(), namespace::PROTOCOL),
        (assertion_xmlns.as_str(), namespace::ASSERTION),
        ("ID", input.response_id),
        ("Version", VERSION),
        ("IssueInstant", input.issue_instant),
        ("Destination", input.destination),
    ];
    if let Some(in_response_to) = input.in_response_to {
        response_attrs.push(("InResponseTo", in_response_to));
    }

    let mut writer = XmlWriter::new();
    writer.start(&response_name, &response_attrs);
    writer.text_element(&qname(input.assertion_prefix, "Issuer"), &[], input.issuer);
    write_status(&mut writer, input.protocol_prefix, input.status);

    writer.start(
        &assertion_name,
        &[
            ("xmlns:xsi", XMLNS_XSI),
            ("xmlns:xs", XMLNS_XS),
            (assertion_xmlns.as_str(), namespace::ASSERTION),
            ("ID", input.assertion_id),
            ("Version", VERSION),
            ("IssueInstant", input.issue_instant),
        ],
    );
    writer.text_element(&qname(input.assertion_prefix, "Issuer"), &[], input.issuer);
    writer.start(&qname(input.assertion_prefix, "Subject"), &[]);
    let name_id_attrs: Vec<(&str, &str)> = [
        ("NameQualifier", input.name_id_qualifiers.name_qualifier),
        (
            "SPNameQualifier",
            input.name_id_qualifiers.sp_name_qualifier,
        ),
        ("Format", input.name_id_format),
        ("SPProvidedID", input.name_id_qualifiers.sp_provided_id),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name, value)))
    .collect();
    writer.text_element(
        &qname(input.assertion_prefix, "NameID"),
        &name_id_attrs,
        input.name_id,
    );
    writer.start(
        &qname(input.assertion_prefix, "SubjectConfirmation"),
        &[("Method", BEARER_CONFIRMATION)],
    );
    let mut confirmation_attrs = vec![
        ("NotOnOrAfter", input.subject_confirmation_not_on_or_after),
        ("Recipient", input.subject_recipient),
    ];
    if let Some(in_response_to) = input.in_response_to {
        confirmation_attrs.push(("InResponseTo", in_response_to));
    }
    writer.empty(
        &qname(input.assertion_prefix, "SubjectConfirmationData"),
        &confirmation_attrs,
    );
    writer.end(&qname(input.assertion_prefix, "SubjectConfirmation"));
    writer.end(&qname(input.assertion_prefix, "Subject"));
    writer.start(
        &qname(input.assertion_prefix, "Conditions"),
        &[
            ("NotBefore", input.conditions_not_before),
            ("NotOnOrAfter", input.conditions_not_on_or_after),
        ],
    );
    writer.start(&qname(input.assertion_prefix, "AudienceRestriction"), &[]);
    writer.text_element(
        &qname(input.assertion_prefix, "Audience"),
        &[],
        input.audience,
    );
    writer.end(&qname(input.assertion_prefix, "AudienceRestriction"));
    writer.end(&qname(input.assertion_prefix, "Conditions"));
    if let Some(statement) = input.authn_statement.as_ref() {
        write_authn_statement(&mut writer, input.assertion_prefix, statement);
    }
    write_login_response_attribute_statement(
        &mut writer,
        input.attributes,
        input.user_attributes,
        input.assertion_prefix,
    )?;
    write_attribute_statement(&mut writer, input.assertion_prefix, input.typed_attributes)?;
    writer.end(&assertion_name);
    writer.end(&response_name);
    Ok(writer.finish())
}

pub(super) struct ErrorLoginResponseXml<'a> {
    pub(super) protocol_prefix: &'a str,
    pub(super) assertion_prefix: &'a str,
    pub(super) response_id: &'a str,
    pub(super) issue_instant: &'a str,
    pub(super) destination: &'a str,
    pub(super) issuer: &'a str,
    pub(super) status: &'a Status,
    pub(super) in_response_to: Option<&'a str>,
}

pub(super) fn render_error_login_response(
    input: &ErrorLoginResponseXml<'_>,
) -> Result<String, SamlError> {
    let response_name = qname(input.protocol_prefix, "Response");
    let protocol_xmlns = format!("xmlns:{}", input.protocol_prefix);
    let assertion_xmlns = format!("xmlns:{}", input.assertion_prefix);
    let mut response_attrs = vec![
        (protocol_xmlns.as_str(), namespace::PROTOCOL),
        (assertion_xmlns.as_str(), namespace::ASSERTION),
        ("ID", input.response_id),
        ("Version", VERSION),
        ("IssueInstant", input.issue_instant),
        ("Destination", input.destination),
    ];
    if let Some(in_response_to) = input.in_response_to {
        response_attrs.push(("InResponseTo", in_response_to));
    }

    let mut writer = XmlWriter::new();
    writer.start(&response_name, &response_attrs);
    writer.text_element(&qname(input.assertion_prefix, "Issuer"), &[], input.issuer);
    write_status(&mut writer, input.protocol_prefix, input.status);
    writer.end(&response_name);
    Ok(writer.finish())
}

fn write_status(writer: &mut XmlWriter, protocol_prefix: &str, status: &Status) {
    let status_name = qname(protocol_prefix, "Status");
    let status_code_name = qname(protocol_prefix, "StatusCode");
    writer.start(&status_name, &[]);
    match status.subordinate() {
        Some(subordinate) => {
            writer.start(&status_code_name, &[("Value", status.top_level().as_uri())]);
            writer.empty(&status_code_name, &[("Value", subordinate.as_uri())]);
            writer.end(&status_code_name);
        }
        None => writer.empty(&status_code_name, &[("Value", status.top_level().as_uri())]),
    }
    writer.end(&status_name);
}

fn write_authn_statement(writer: &mut XmlWriter, prefix: &str, statement: &AuthnStatementXml<'_>) {
    let name = qname(prefix, "AuthnStatement");
    let mut attrs = vec![("AuthnInstant", statement.authn_instant)];
    if let Some(session_index) = statement.session_index {
        attrs.push(("SessionIndex", session_index));
    }
    writer.start(&name, &attrs);
    writer.start(&qname(prefix, "AuthnContext"), &[]);
    let reference_name = match statement.authn_context.kind() {
        AuthnContextReferenceKind::Class => "AuthnContextClassRef",
        AuthnContextReferenceKind::Declaration => "AuthnContextDeclRef",
    };
    writer.text_element(
        &qname(prefix, reference_name),
        &[],
        statement.authn_context.uri(),
    );
    writer.end(&qname(prefix, "AuthnContext"));
    writer.end(&name);
}

/// Write `attributes` as one `<AttributeStatement>`. No attributes writes
/// nothing.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when a `NameFormat` is not an absolute URI
/// reference, or a basic attribute name is not an `xs:Name`.
fn write_attribute_statement(
    writer: &mut XmlWriter,
    prefix: &str,
    attributes: &[Attribute],
) -> Result<(), SamlError> {
    if attributes.is_empty() {
        return Ok(());
    }
    let statement_name = qname(prefix, "AttributeStatement");
    let attribute_name = qname(prefix, "Attribute");
    let value_name = qname(prefix, "AttributeValue");
    writer.start(&statement_name, &[]);
    for attribute in attributes {
        if let Some(name_format) = attribute.name_format() {
            if !is_absolute_uri_reference(name_format) {
                return Err(SamlError::Invalid(format!(
                    "attribute `{}` NameFormat must be an absolute URI reference with at least one non-whitespace character",
                    attribute.name()
                )));
            }
        }
        if attribute.name_format() == Some(attribute_name_format::BASIC)
            && !is_name(attribute.name())
        {
            return Err(SamlError::Invalid(format!(
                "basic attribute name `{}` is not an XML name",
                attribute.name()
            )));
        }
        let mut attrs = vec![("Name", attribute.name())];
        if let Some(name_format) = attribute.name_format() {
            attrs.push(("NameFormat", name_format));
        }
        if attribute.values().is_empty() {
            writer.empty(&attribute_name, &attrs);
            continue;
        }
        writer.start(&attribute_name, &attrs);
        for value in attribute.values() {
            writer.text_element(
                &value_name,
                &[
                    ("xmlns:xs", XMLNS_XS),
                    ("xmlns:xsi", XMLNS_XSI),
                    ("xsi:type", "xs:string"),
                ],
                value.as_str(),
            );
        }
        writer.end(&attribute_name);
    }
    writer.end(&statement_name);
    Ok(())
}

fn qname(prefix: &str, local_name: &str) -> String {
    format!("{prefix}:{local_name}")
}
