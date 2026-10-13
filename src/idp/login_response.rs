use crate::constants::namespace;
use crate::error::SamlError;
use crate::model::Status;
use crate::template::{write_login_response_attribute_statement, LoginResponseAttribute};
use crate::xml::write::XmlWriter;

const VERSION: &str = "2.0";
const XMLNS_XS: &str = "http://www.w3.org/2001/XMLSchema";
const XMLNS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const BEARER_CONFIRMATION: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const UNSPECIFIED_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

pub(super) struct AuthnStatementXml<'a> {
    pub(super) authn_instant: &'a str,
    pub(super) session_index: Option<&'a str>,
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
    pub(super) in_response_to: Option<&'a str>,
    pub(super) authn_statement: Option<AuthnStatementXml<'a>>,
    pub(super) attributes: &'a [LoginResponseAttribute],
    pub(super) user_attributes: &'a [(String, String)],
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
    let name_id_attrs: Vec<(&str, &str)> = input
        .name_id_format
        .map(|format| ("Format", format))
        .into_iter()
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
    writer.text_element(
        &qname(prefix, "AuthnContextClassRef"),
        &[],
        UNSPECIFIED_AUTHN_CONTEXT,
    );
    writer.end(&qname(prefix, "AuthnContext"));
    writer.end(&name);
}

fn qname(prefix: &str, local_name: &str) -> String {
    format!("{prefix}:{local_name}")
}
