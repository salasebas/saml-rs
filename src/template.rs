//! Default SAML message templates and tag substitution.
//!
//! `{Tag}` placeholders are filled by [`replace_tags_by_value`] or
//! [`replace_tags_by_optional_value`]. Replacement values are XML-escaped in
//! both attribute and element-text positions so caller-provided data cannot
//! become signed SAML markup. Text inserted for a value is not scanned for
//! further placeholders.

use crate::binding::xml_escape;
use crate::error::SamlError;
use crate::util::camel_case;
use crate::xml::write::XmlWriter;

/// Default `<AuthnRequest>` template.
pub const LOGIN_REQUEST_TEMPLATE: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" ForceAuthn=\"{ForceAuthn}\" ProtocolBinding=\"{ProtocolBinding}\" AssertionConsumerServiceURL=\"{AssertionConsumerServiceURL}\" AssertionConsumerServiceIndex=\"{AssertionConsumerServiceIndex}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format=\"{NameIDFormat}\" AllowCreate=\"{AllowCreate}\"/></samlp:AuthnRequest>";

/// Default `<LogoutRequest>` template.
pub const LOGOUT_REQUEST_TEMPLATE: &str = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>";

/// Default `<AttributeStatement>` wrapper template.
pub const ATTRIBUTE_STATEMENT_TEMPLATE: &str =
    "<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>";

/// Default `<Attribute>` template.
pub const ATTRIBUTE_TEMPLATE: &str = "<saml:Attribute Name=\"{Name}\" NameFormat=\"{NameFormat}\"><saml:AttributeValue xmlns:xs=\"{ValueXmlnsXs}\" xmlns:xsi=\"{ValueXmlnsXsi}\" xsi:type=\"{ValueXsiType}\">{Value}</saml:AttributeValue></saml:Attribute>";

const DEFAULT_XS: &str = "http://www.w3.org/2001/XMLSchema";
const DEFAULT_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Default login `<Response>` template.
pub const LOGIN_RESPONSE_TEMPLATE: &str = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status><saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{AssertionID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"{SubjectConfirmationDataNotOnOrAfter}\" Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{ConditionsNotBefore}\" NotOnOrAfter=\"{ConditionsNotOnOrAfter}\"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>";

/// Default `<LogoutResponse>` template.
pub const LOGOUT_RESPONSE_TEMPLATE: &str = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status></samlp:LogoutResponse>";

/// Rewrite known SAML template prefixes while preserving namespace URIs.
pub(crate) fn apply_tag_prefixes(
    xml: &str,
    protocol_prefix: &str,
    assertion_prefix: &str,
) -> String {
    xml.replace("<samlp:", &format!("<{protocol_prefix}:"))
        .replace("</samlp:", &format!("</{protocol_prefix}:"))
        .replace("xmlns:samlp=", &format!("xmlns:{protocol_prefix}="))
        .replace("<saml:", &format!("<{assertion_prefix}:"))
        .replace("</saml:", &format!("</{assertion_prefix}:"))
        .replace("xmlns:saml=", &format!("xmlns:{assertion_prefix}="))
}

pub(crate) fn validate_tag_prefix(name: &str, prefix: &str) -> Result<(), SamlError> {
    if prefix.is_empty() {
        return Err(SamlError::Invalid(format!(
            "{name} tag prefix cannot be empty"
        )));
    }
    if prefix
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | '/' | ':'))
    {
        return Err(SamlError::Invalid(format!(
            "{name} tag prefix contains an invalid character"
        )));
    }
    Ok(())
}

/// Replace `{key}` placeholders in `raw_xml`.
///
/// Placeholder replacement text is XML-escaped before insertion and is not
/// scanned for `{key}` tokens. XML fragments such as generated attribute
/// statements must be spliced into templates before calling this helper.
pub fn replace_tags_by_value(raw_xml: &str, tags: &[(&str, String)]) -> String {
    let mut xml = conceal_existing_markers(raw_xml);
    for (key, value) in tags {
        xml = replace_tag(&xml, key, Some(value));
    }
    reveal_concealed_text(xml)
}

/// Replace `{key}` placeholders in `raw_xml`, omitting optional placeholders.
///
/// `Some(value)` is XML-escaped and inserted, including `Some(String::new())`.
/// Inserted text is not scanned for `{key}` tokens. `None` removes attributes
/// whose complete value is the placeholder, removes elements whose complete
/// body is the placeholder, and renders any remaining occurrences as an empty
/// string.
pub fn replace_tags_by_optional_value(raw_xml: &str, tags: &[(&str, Option<String>)]) -> String {
    let mut xml = conceal_existing_markers(raw_xml);
    for (key, value) in tags {
        xml = replace_tag(&xml, key, value.as_deref());
    }
    reveal_concealed_text(xml)
}

/// Marker that hides `{` in inserted text.
///
/// `0` after the marker restores a marker that was already present. `1`
/// restores `{`.
const CONCEALED_BRACE: char = '\u{E000}';

fn conceal_existing_markers(raw: &str) -> String {
    if !raw.contains(CONCEALED_BRACE) {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == CONCEALED_BRACE {
            out.push(CONCEALED_BRACE);
            out.push('0');
        } else {
            out.push(ch);
        }
    }
    out
}

fn conceal_inserted_braces(escaped: &str) -> String {
    if !escaped.chars().any(|ch| ch == '{' || ch == CONCEALED_BRACE) {
        return escaped.to_string();
    }
    let mut out = String::with_capacity(escaped.len());
    for ch in escaped.chars() {
        match ch {
            CONCEALED_BRACE => {
                out.push(CONCEALED_BRACE);
                out.push('0');
            }
            '{' => {
                out.push(CONCEALED_BRACE);
                out.push('1');
            }
            other => out.push(other),
        }
    }
    out
}

fn reveal_concealed_text(raw: String) -> String {
    if !raw.contains(CONCEALED_BRACE) {
        return raw;
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != CONCEALED_BRACE {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push(CONCEALED_BRACE),
            Some('1') => out.push('{'),
            Some(other) => {
                out.push(CONCEALED_BRACE);
                out.push(other);
            }
            None => out.push(CONCEALED_BRACE),
        }
    }
    out
}

fn replace_tag(raw_xml: &str, key: &str, value: Option<&str>) -> String {
    let needle = format!("{{{key}}}");
    match value {
        Some(value) => replace_all(
            raw_xml,
            &needle,
            &conceal_inserted_braces(&xml_escape(value)),
        ),
        None => {
            let xml = remove_optional_attributes(raw_xml, &needle);
            let xml = remove_optional_elements(&xml, &needle);
            replace_all(&xml, &needle, "")
        }
    }
}

fn replace_all(raw_xml: &str, needle: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(raw_xml.len());
    let mut rest = raw_xml;
    while let Some(pos) = rest.find(needle) {
        result.push_str(&rest[..pos]);
        result.push_str(replacement);
        rest = &rest[pos + needle.len()..];
    }
    result.push_str(rest);
    result
}

fn remove_optional_attributes(raw_xml: &str, needle: &str) -> String {
    remove_optional_ranges(raw_xml, needle, optional_attribute_range)
}

fn remove_optional_elements(raw_xml: &str, needle: &str) -> String {
    remove_optional_ranges(raw_xml, needle, optional_element_range)
}

fn remove_optional_ranges(
    raw_xml: &str,
    needle: &str,
    range_for_match: fn(&str, usize, usize) -> Option<(usize, usize)>,
) -> String {
    let mut result = String::with_capacity(raw_xml.len());
    let mut cursor = 0;
    while let Some(relative_pos) = raw_xml[cursor..].find(needle) {
        let pos = cursor + relative_pos;
        if let Some((start, end)) = range_for_match(raw_xml, pos, needle.len()) {
            if start >= cursor {
                result.push_str(&raw_xml[cursor..start]);
                cursor = end;
                continue;
            }
        }
        let next = pos + needle.len();
        result.push_str(&raw_xml[cursor..next]);
        cursor = next;
    }
    result.push_str(&raw_xml[cursor..]);
    result
}

fn optional_attribute_range(
    raw_xml: &str,
    needle_start: usize,
    needle_len: usize,
) -> Option<(usize, usize)> {
    let bytes = raw_xml.as_bytes();
    let needle_end = needle_start + needle_len;
    if needle_start == 0 || needle_end >= bytes.len() {
        return None;
    }

    let quote = bytes[needle_start - 1];
    if !matches!(quote, b'"' | b'\'') || bytes[needle_end] != quote {
        return None;
    }

    let mut cursor = needle_start - 1;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor == 0 || bytes[cursor - 1] != b'=' {
        return None;
    }

    let mut name_end = cursor - 1;
    while name_end > 0 && bytes[name_end - 1].is_ascii_whitespace() {
        name_end -= 1;
    }

    let mut name_start = name_end;
    while name_start > 0 && is_attribute_name_byte(bytes[name_start - 1]) {
        name_start -= 1;
    }
    if name_start == name_end {
        return None;
    }

    let mut remove_start = name_start;
    while remove_start > 0 && bytes[remove_start - 1].is_ascii_whitespace() {
        remove_start -= 1;
    }

    Some((remove_start, needle_end + 1))
}

fn is_attribute_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.')
}

fn optional_element_range(
    raw_xml: &str,
    needle_start: usize,
    needle_len: usize,
) -> Option<(usize, usize)> {
    let bytes = raw_xml.as_bytes();
    let needle_end = needle_start + needle_len;
    if needle_start == 0
        || needle_end >= bytes.len()
        || bytes[needle_start - 1] != b'>'
        || bytes[needle_end] != b'<'
    {
        return None;
    }

    let open_start = raw_xml[..needle_start - 1].rfind('<')?;
    let name_start = open_start + 1;
    let first_name_byte = *bytes.get(name_start)?;
    if matches!(first_name_byte, b'/' | b'!' | b'?') {
        return None;
    }

    let mut name_end = name_start;
    while name_end < bytes.len()
        && !bytes[name_end].is_ascii_whitespace()
        && !matches!(bytes[name_end], b'/' | b'>')
    {
        name_end += 1;
    }
    if name_start == name_end {
        return None;
    }

    let element_name = &raw_xml[name_start..name_end];
    let close_tag = format!("</{element_name}>");
    raw_xml[needle_end..]
        .starts_with(&close_tag)
        .then_some((open_start, needle_end + close_tag.len()))
}

/// A single `<Attribute>` to render in a login response.
#[derive(Debug, Clone)]
pub struct LoginResponseAttribute {
    /// `Name` attribute.
    pub name: String,
    /// `NameFormat` attribute.
    pub name_format: String,
    /// `xsi:type` of the value.
    pub value_xsi_type: String,
    /// Tag whose runtime value fills the `AttributeValue` (becomes `{attr<Tag>}`).
    pub value_tag: String,
    /// Optional `xmlns:xs` override.
    pub value_xmlns_xs: Option<String>,
    /// Optional `xmlns:xsi` override.
    pub value_xmlns_xsi: Option<String>,
}

fn tagging(prefix: &str, content: &str) -> String {
    let camel = camel_case(content);
    let mut chars = camel.chars();
    match chars.next() {
        Some(first) => {
            let mut out = prefix.to_string();
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        }
        None => prefix.to_string(),
    }
}

/// Placeholder key (without braces) for an attribute value tag:
/// `attr<CamelCase>`. The runtime value fills `{<key>}`.
pub fn attr_tag(value_tag: &str) -> String {
    tagging("attr", value_tag)
}

/// IdP login `<Response>` template config.
#[derive(Debug, Clone, Default)]
pub struct LoginResponseTemplate {
    /// Custom `<Response>` template; `None` uses [`LOGIN_RESPONSE_TEMPLATE`].
    pub context: Option<String>,
    /// Attributes rendered into the assertion's `<AttributeStatement>`.
    pub attributes: Vec<LoginResponseAttribute>,
}

/// Build an `<AttributeStatement>` from `attributes`.
///
/// Each attribute's value becomes a new `{attr<Tag>}` placeholder to be filled
/// later by [`replace_tags_by_value`].
pub fn attribute_statement_builder(
    attributes: &[LoginResponseAttribute],
    attribute_template: &str,
    attribute_statement_template: &str,
) -> String {
    let attrs: String = attributes
        .iter()
        .map(|a| {
            let value_placeholder = format!("{{{}}}", tagging("attr", &a.value_tag));
            let name = xml_escape(&a.name);
            let name_format = xml_escape(&a.name_format);
            let value_xmlns_xs = xml_escape(a.value_xmlns_xs.as_deref().unwrap_or(DEFAULT_XS));
            let value_xmlns_xsi = xml_escape(a.value_xmlns_xsi.as_deref().unwrap_or(DEFAULT_XSI));
            let value_xsi_type = xml_escape(&a.value_xsi_type);
            attribute_template
                .replacen("{Name}", &name, 1)
                .replacen("{NameFormat}", &name_format, 1)
                .replacen("{ValueXmlnsXs}", &value_xmlns_xs, 1)
                .replacen("{ValueXmlnsXsi}", &value_xmlns_xsi, 1)
                .replacen("{ValueXsiType}", &value_xsi_type, 1)
                .replacen("{Value}", &value_placeholder, 1)
        })
        .collect();
    attribute_statement_template.replacen("{Attributes}", &attrs, 1)
}

pub(crate) fn write_login_response_attribute_statement(
    writer: &mut XmlWriter,
    attributes: &[LoginResponseAttribute],
    user_attributes: &[(String, String)],
    assertion_prefix: &str,
) -> Result<(), SamlError> {
    if attributes.is_empty() {
        return Ok(());
    }

    let statement_name = format!("{assertion_prefix}:AttributeStatement");
    let attribute_name = format!("{assertion_prefix}:Attribute");
    let value_name = format!("{assertion_prefix}:AttributeValue");
    writer.start(&statement_name, &[]);
    for attribute in attributes {
        let value = user_attributes
            .iter()
            .find(|(tag, _)| tag == &attribute.value_tag)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| {
                SamlError::Invalid(format!(
                    "missing login response attribute value for `{}`",
                    attribute.value_tag
                ))
            })?;
        writer.start(
            &attribute_name,
            &[
                ("Name", attribute.name.as_str()),
                ("NameFormat", attribute.name_format.as_str()),
            ],
        );
        writer.text_element(
            &value_name,
            &[
                (
                    "xmlns:xs",
                    attribute.value_xmlns_xs.as_deref().unwrap_or(DEFAULT_XS),
                ),
                (
                    "xmlns:xsi",
                    attribute.value_xmlns_xsi.as_deref().unwrap_or(DEFAULT_XSI),
                ),
                ("xsi:type", attribute.value_xsi_type.as_str()),
            ],
            value,
        );
        writer.end(&attribute_name);
    }
    writer.end(&statement_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_values_are_escaped_in_attributes_and_element_text() {
        let rendered = replace_tags_by_value(
            "<a X=\"{V}\">{T}</a>",
            &[
                ("V", "a\"b&c<d".to_string()),
                ("T", "<raw>&amp;".to_string()),
            ],
        );
        assert_eq!(
            rendered,
            "<a X=\"a&quot;b&amp;c&lt;d\">&lt;raw&gt;&amp;amp;</a>"
        );
    }

    #[test]
    fn optional_replacement_values_are_escaped_in_attributes_and_element_text() {
        let rendered = replace_tags_by_optional_value(
            "<a X=\"{V}\">{T}</a>",
            &[
                ("V", Some("a\"b&c<d".to_string())),
                ("T", Some("<raw>&amp;".to_string())),
            ],
        );
        assert_eq!(
            rendered,
            "<a X=\"a&quot;b&amp;c&lt;d\">&lt;raw&gt;&amp;amp;</a>"
        );
    }

    #[test]
    fn optional_none_removes_placeholder_attribute_but_keeps_visible_text() {
        let rendered =
            replace_tags_by_optional_value("<a id=\"{Id}\">visible</a>", &[("Id", None)]);
        assert_eq!(rendered, "<a>visible</a>");
    }

    #[test]
    fn optional_none_removes_element_when_placeholder_is_only_body() {
        let rendered =
            replace_tags_by_optional_value("<root><a>{Body}</a><b>x</b></root>", &[("Body", None)]);
        assert_eq!(rendered, "<root><b>x</b></root>");
    }

    #[test]
    fn optional_none_in_mixed_text_becomes_empty_string() {
        let rendered = replace_tags_by_optional_value("<a>Hello {Name}</a>", &[("Name", None)]);
        assert_eq!(rendered, "<a>Hello </a>");
    }

    #[test]
    fn optional_empty_string_keeps_empty_attribute_value() {
        let rendered = replace_tags_by_optional_value(
            "<a id=\"{Id}\">visible</a>",
            &[("Id", Some(String::new()))],
        );
        assert_eq!(rendered, "<a id=\"\">visible</a>");
    }

    #[test]
    fn renders_full_authn_request() {
        let xml = replace_tags_by_optional_value(
            LOGIN_REQUEST_TEMPLATE,
            &[
                ("ID", Some("_abc".to_string())),
                ("IssueInstant", Some("2024-01-01T00:00:00Z".to_string())),
                (
                    "Destination",
                    Some("https://idp.example.com/sso".to_string()),
                ),
                ("ForceAuthn", Some("true".to_string())),
                (
                    "ProtocolBinding",
                    Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
                ),
                (
                    "AssertionConsumerServiceURL",
                    Some("https://sp.example.com/acs".to_string()),
                ),
                ("AssertionConsumerServiceIndex", None),
                (
                    "Issuer",
                    Some("https://sp.example.com/metadata".to_string()),
                ),
                (
                    "NameIDFormat",
                    Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()),
                ),
                ("AllowCreate", Some("true".to_string())),
            ],
        );
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        assert!(xml.contains("ID=\"_abc\""));
        assert!(xml.contains("Destination=\"https://idp.example.com/sso\""));
        assert!(xml.contains("ForceAuthn=\"true\""));
        assert!(xml.contains("<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>"));
        assert!(!xml.contains("AssertionConsumerServiceIndex="));
        assert!(!xml.contains('{'));
    }

    #[test]
    fn builds_attribute_statement_with_value_placeholder() {
        let attrs = vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }];
        let built =
            attribute_statement_builder(&attrs, ATTRIBUTE_TEMPLATE, ATTRIBUTE_STATEMENT_TEMPLATE);
        assert!(built.starts_with("<saml:AttributeStatement>"));
        assert!(built.contains("Name=\"mail\""));
        assert!(built.contains("xsi:type=\"xs:string\""));
        // value_tag -> {attrUserEmail}
        assert!(built.contains("{attrUserEmail}"));
    }

    #[test]
    fn inserted_values_are_not_scanned_for_later_placeholders() {
        let rendered = replace_tags_by_value(
            "<n>{NameID}</n><a>{attrRole}</a><m>{attrMail}</m><r>{InResponseTo}</r>",
            &[
                ("NameID", "a<b>{InResponseTo}".to_string()),
                ("attrRole", "admin-{attrMail}".to_string()),
                ("attrMail", "user".to_string()),
                ("InResponseTo", "_req".to_string()),
            ],
        );
        assert_eq!(
            rendered,
            "<n>a&lt;b&gt;{InResponseTo}</n><a>admin-{attrMail}</a><m>user</m><r>_req</r>"
        );
    }

    #[test]
    fn optional_inserted_values_are_not_scanned_for_later_placeholders() {
        let rendered = replace_tags_by_optional_value(
            "<root><n>{NameID}</n><s>{SessionIndex}</s></root>",
            &[
                ("NameID", Some("{SessionIndex}".to_string())),
                ("SessionIndex", Some("abc".to_string())),
            ],
        );
        assert_eq!(rendered, "<root><n>{SessionIndex}</n><s>abc</s></root>");
    }

    #[test]
    fn optional_none_still_drops_an_element_after_a_value_containing_its_placeholder() {
        let rendered = replace_tags_by_optional_value(
            "<root><n>{NameID}</n><s>{SessionIndex}</s></root>",
            &[
                ("NameID", Some("{SessionIndex}".to_string())),
                ("SessionIndex", None),
            ],
        );
        assert_eq!(rendered, "<root><n>{SessionIndex}</n></root>");
    }

    #[test]
    fn private_use_text_and_template_markers_round_trip_through_substitution() {
        let rendered = replace_tags_by_value(
            "<a>\u{E000}1{V}{Tail}</a>",
            &[
                ("V", "\u{E000}{Tail}".to_string()),
                ("Tail", "end".to_string()),
            ],
        );
        assert_eq!(rendered, "<a>\u{E000}1\u{E000}{Tail}end</a>");
    }
}
