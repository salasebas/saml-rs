use crate::constants::namespace;
use crate::entity::{EntitySetting, User};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::Status;
use crate::template::validate_tag_prefix;
use crate::xml::write::XmlWriter;
use crate::xml::OutboundNameIdQualifiers;

pub(super) fn issuer_of(setting: &EntitySetting, meta: &Metadata) -> String {
    setting
        .entity_id
        .clone()
        .or_else(|| meta.get_entity_id().map(str::to_string))
        .unwrap_or_default()
}

pub(super) struct LogoutRequestSubject<'a> {
    pub(super) name_id: &'a str,
    pub(super) qualifiers: OutboundNameIdQualifiers<'a>,
    pub(super) session_indexes: Vec<&'a str>,
}

pub(super) struct LogoutRequestTimeAttributes<'a> {
    pub(super) issue_instant: &'a str,
    pub(super) not_on_or_after: Option<&'a str>,
}

impl<'a> LogoutRequestSubject<'a> {
    pub(super) fn from_user(user: &'a User) -> Self {
        Self {
            name_id: &user.name_id,
            qualifiers: OutboundNameIdQualifiers::default(),
            session_indexes: user.session_index.as_deref().into_iter().collect(),
        }
    }
}

pub(super) fn render_default_logout_response(
    setting: &EntitySetting,
    id: &str,
    issue_instant: &str,
    destination: &str,
    in_response_to: Option<&str>,
    issuer: &str,
    status: &Status,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

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
        ("Destination", destination),
    ];
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

pub(super) fn render_default_logout_request(
    setting: &EntitySetting,
    meta: &Metadata,
    id: &str,
    timing: LogoutRequestTimeAttributes<'_>,
    destination: &str,
    subject: &LogoutRequestSubject<'_>,
    name_id_format: Option<&str>,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutRequest");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let name_id_name = format!("{assertion_prefix}:NameID");
    let session_index_name = format!("{protocol_prefix}:SessionIndex");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let issuer = issuer_of(setting, meta);

    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", timing.issue_instant),
        ("Destination", destination),
    ];
    if let Some(value) = timing.not_on_or_after {
        // SAML Core 2.0 §3.7.3.2 requires this attribute when the
        // LogoutRequest producer is acting as the Session Authority. The
        // selected lifetime remains saml-rs policy.
        attrs.push(("NotOnOrAfter", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], &issuer);
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
