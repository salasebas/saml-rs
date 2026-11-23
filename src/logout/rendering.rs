use crate::constants::namespace;
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::Status;
use crate::xml::write::{Prefixes, XmlWriter};
use crate::xml::OutboundNameIdQualifiers;

pub(crate) fn issuer_of(setting: &EntitySetting, meta: &Metadata) -> String {
    setting
        .entity_id
        .clone()
        .or_else(|| meta.entity_id().map(str::to_string))
        .unwrap_or_default()
}

pub(crate) struct LogoutRequestSubject<'a> {
    pub(crate) name_id: &'a str,
    pub(crate) qualifiers: OutboundNameIdQualifiers<'a>,
    pub(crate) session_indexes: Vec<&'a str>,
}

pub(crate) struct LogoutRequestAttributes<'a> {
    pub(crate) id: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) issue_instant: &'a str,
    pub(crate) not_on_or_after: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
    pub(crate) asynchronous: bool,
}

pub(super) struct LogoutResponseAttributes<'a> {
    pub(super) id: &'a str,
    pub(super) issue_instant: &'a str,
    pub(super) destination: Option<&'a str>,
    pub(super) in_response_to: Option<&'a str>,
}

pub(super) fn render_logout_response(
    setting: &EntitySetting,
    response: LogoutResponseAttributes<'_>,
    issuer: &str,
    status: &Status,
    status_message: Option<&str>,
) -> Result<String, SamlError> {
    let prefixes = Prefixes::of(setting)?;
    let root_name = prefixes.protocol("LogoutResponse");
    let issuer_name = prefixes.assertion("Issuer");
    let xmlns_protocol = prefixes.xmlns_protocol();
    let xmlns_assertion = prefixes.xmlns_assertion();
    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", response.id),
        ("Version", "2.0"),
        ("IssueInstant", response.issue_instant),
    ];
    if let Some(value) = response.destination {
        attrs.push(("Destination", value));
    }
    if let Some(value) = response.in_response_to {
        attrs.push(("InResponseTo", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], issuer);
    writer.status(&prefixes, status, status_message);
    writer.end(&root_name);
    Ok(writer.finish())
}

pub(crate) fn render_logout_request(
    setting: &EntitySetting,
    issuer: &str,
    attributes: LogoutRequestAttributes<'_>,
    subject: &LogoutRequestSubject<'_>,
    name_id_format: Option<&str>,
) -> Result<String, SamlError> {
    let LogoutRequestAttributes {
        id,
        destination,
        issue_instant,
        not_on_or_after,
        reason,
        asynchronous,
    } = attributes;
    let prefixes = Prefixes::of(setting)?;
    let root_name = prefixes.protocol("LogoutRequest");
    let issuer_name = prefixes.assertion("Issuer");
    let name_id_name = prefixes.assertion("NameID");
    let session_index_name = prefixes.protocol("SessionIndex");
    let xmlns_protocol = prefixes.xmlns_protocol();
    let xmlns_assertion = prefixes.xmlns_assertion();

    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
        ("Destination", destination),
    ];
    if let Some(value) = not_on_or_after {
        // SAML Core 2.0 §3.7.3.2 requires this attribute when the
        // LogoutRequest producer is acting as the Session Authority. The
        // selected lifetime remains saml-rs policy.
        attrs.push(("NotOnOrAfter", value));
    }
    if let Some(value) = reason {
        attrs.push(("Reason", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], issuer);
    if asynchronous {
        let extensions_name = prefixes.protocol("Extensions");
        writer.start(&extensions_name, &[]);
        writer.empty(
            "aslo:Asynchronous",
            &[(
                "xmlns:aslo",
                "urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo",
            )],
        );
        writer.end(&extensions_name);
    }
    let qualifiers = subject.qualifiers;
    let mut name_id_attrs = Vec::with_capacity(4);
    if let Some(value) = qualifiers.name_qualifier {
        name_id_attrs.push(("NameQualifier", value));
    }
    if let Some(value) = qualifiers.sp_name_qualifier {
        name_id_attrs.push(("SPNameQualifier", value));
    }
    if let Some(value) = name_id_format {
        name_id_attrs.push(("Format", value));
    }
    if let Some(value) = qualifiers.sp_provided_id {
        name_id_attrs.push(("SPProvidedID", value));
    }
    writer.text_element(&name_id_name, &name_id_attrs, subject.name_id);
    for session_index in &subject.session_indexes {
        writer.text_element(&session_index_name, &[], session_index);
    }
    writer.end(&root_name);
    Ok(writer.finish())
}
