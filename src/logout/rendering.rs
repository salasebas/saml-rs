use quick_xml::events::Event;
use quick_xml::Reader;

use crate::constants::namespace;
use crate::entity::EntitySetting;
use crate::error::{xml_err, SamlError};
use crate::metadata::Metadata;
use crate::model::Status;
use crate::template::{render_template, validate_tag_prefixes};
use crate::xml::write::{Prefixes, XmlWriter};
use crate::xml::{utf8_bom_len, OutboundNameIdQualifiers};

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
}

pub(super) fn render_default_logout_response(
    setting: &EntitySetting,
    id: &str,
    issue_instant: &str,
    destination: Option<&str>,
    in_response_to: Option<&str>,
    issuer: &str,
    status: &Status,
) -> Result<String, SamlError> {
    validate_tag_prefixes(&setting.tag_prefix_protocol, &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutResponse");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
    ];
    if let Some(value) = destination {
        attrs.push(("Destination", value));
    }
    if let Some(value) = in_response_to {
        attrs.push(("InResponseTo", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], issuer);
    write_logout_status(&mut writer, protocol_prefix, status);
    writer.end(&root_name);
    Ok(writer.finish())
}

fn write_logout_status(writer: &mut XmlWriter, protocol_prefix: &str, status: &Status) {
    let status_name = format!("{protocol_prefix}:Status");
    let status_code_name = format!("{protocol_prefix}:StatusCode");
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
    } = attributes;
    if let Some(template) = setting.logout_request_template.as_deref() {
        if subject.session_indexes.len() > 1 {
            return Err(SamlError::Unsupported(
                "custom LogoutRequest templates cannot render multiple SessionIndex values".into(),
            ));
        }
        let mut replacements = vec![
            ("ID", Some(id.to_owned())),
            ("IssueInstant", Some(issue_instant.to_owned())),
            ("Destination", Some(destination.to_owned())),
            ("Issuer", Some(issuer.to_owned())),
            ("NameIDFormat", name_id_format.map(str::to_string)),
            ("NameID", Some(subject.name_id.to_string())),
            (
                "NameQualifier",
                subject.qualifiers.name_qualifier.map(str::to_string),
            ),
            (
                "SPNameQualifier",
                subject.qualifiers.sp_name_qualifier.map(str::to_string),
            ),
            (
                "SPProvidedID",
                subject.qualifiers.sp_provided_id.map(str::to_string),
            ),
            (
                "SessionIndex",
                subject
                    .session_indexes
                    .first()
                    .map(|value| (*value).to_string()),
            ),
        ];
        if let Some(expiration) = not_on_or_after {
            replacements.push(("NotOnOrAfter", Some(expiration.to_owned())));
        }
        let xml = render_template(template, Prefixes::of(setting)?, &replacements)?;
        return match reason {
            Some(reason) => add_template_reason(xml, reason),
            None => Ok(xml),
        };
    }
    validate_tag_prefixes(&setting.tag_prefix_protocol, &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutRequest");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let name_id_name = format!("{assertion_prefix}:NameID");
    let session_index_name = format!("{protocol_prefix}:SessionIndex");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");

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

fn add_template_reason(mut xml: String, reason: &str) -> Result<String, SamlError> {
    let bom_len = utf8_bom_len(&xml);
    let mut reader = Reader::from_str(&xml);
    loop {
        let before = usize::try_from(reader.buffer_position()).map_err(xml_err)?;
        match reader.read_event().map_err(xml_err)? {
            Event::Start(root) => {
                if root.try_get_attribute("Reason").map_err(xml_err)?.is_none() {
                    let mut root = root.into_owned();
                    root.push_attribute(("Reason", reason));
                    let after = usize::try_from(reader.buffer_position()).map_err(xml_err)?;
                    xml.replace_range(bom_len + before + 1..bom_len + after - 1, &root);
                }
                break;
            }
            Event::Empty(_) | Event::Eof => break,
            _ => {}
        }
    }
    Ok(xml)
}
