//! Default SAML message templates and tag substitution.
//!
//! `{Tag}` placeholders are filled by [`replace_tags_by_optional_value`].
//! Replacement values are XML-escaped in
//! both attribute and element-text positions so caller-provided data cannot
//! become signed SAML markup. Text inserted for a value is not scanned for
//! further placeholders.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::binding::xml_escape;
use crate::error::{xml_err, SamlError};
#[cfg(test)]
use crate::util::camel_case;
use crate::xml::name::validate_namespace_prefix;

/// Raw `<AuthnRequest>` template for standalone tag substitution.
#[cfg(test)]
pub const LOGIN_REQUEST_TEMPLATE: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" ForceAuthn=\"{ForceAuthn}\" ProtocolBinding=\"{ProtocolBinding}\" AssertionConsumerServiceURL=\"{AssertionConsumerServiceURL}\" AssertionConsumerServiceIndex=\"{AssertionConsumerServiceIndex}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format=\"{NameIDFormat}\" AllowCreate=\"{AllowCreate}\"/></samlp:AuthnRequest>";

/// Default `<LogoutRequest>` template.
pub const LOGOUT_REQUEST_TEMPLATE: &str = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>";

/// Default `<AttributeStatement>` wrapper template.
#[cfg(test)]
pub const ATTRIBUTE_STATEMENT_TEMPLATE: &str =
    "<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>";

/// Default `<Attribute>` template.
#[cfg(test)]
pub const ATTRIBUTE_TEMPLATE: &str = "<saml:Attribute Name=\"{Name}\" NameFormat=\"{NameFormat}\"><saml:AttributeValue xmlns:xs=\"{ValueXmlnsXs}\" xmlns:xsi=\"{ValueXmlnsXsi}\" xsi:type=\"{ValueXsiType}\">{Value}</saml:AttributeValue></saml:Attribute>";

#[cfg(test)]
const DEFAULT_XS: &str = "http://www.w3.org/2001/XMLSchema";
#[cfg(test)]
const DEFAULT_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Default login `<Response>` template.
#[cfg(test)]
pub const LOGIN_RESPONSE_TEMPLATE: &str = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status><saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{AssertionID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"{SubjectConfirmationDataNotOnOrAfter}\" Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{ConditionsNotBefore}\" NotOnOrAfter=\"{ConditionsNotOnOrAfter}\"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>";

/// Default `<LogoutResponse>` template.
pub const LOGOUT_RESPONSE_TEMPLATE: &str = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status></samlp:LogoutResponse>";

/// Rewrite known SAML template prefixes in one pass while preserving namespace
/// URIs.
pub(crate) fn apply_tag_prefixes(
    xml: &str,
    protocol_prefix: &str,
    assertion_prefix: &str,
) -> String {
    let rewrites = [
        ("<samlp:", format!("<{protocol_prefix}:")),
        ("</samlp:", format!("</{protocol_prefix}:")),
        ("xmlns:samlp=", format!("xmlns:{protocol_prefix}=")),
        ("<saml:", format!("<{assertion_prefix}:")),
        ("</saml:", format!("</{assertion_prefix}:")),
        ("xmlns:saml=", format!("xmlns:{assertion_prefix}=")),
    ];
    let mut result = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find(['<', 'x']) {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        match rewrites.iter().find(|(from, _)| rest.starts_with(from)) {
            Some((from, to)) => {
                result.push_str(to);
                rest = &rest[from.len()..];
            }
            None => {
                result.push_str(&rest[..1]);
                rest = &rest[1..];
            }
        }
    }
    result.push_str(rest);
    result
}

pub(crate) fn validate_tag_prefixes(
    protocol_prefix: &str,
    assertion_prefix: &str,
) -> Result<(), SamlError> {
    validate_namespace_prefix("protocol tag prefix", protocol_prefix)?;
    validate_namespace_prefix("assertion tag prefix", assertion_prefix)?;
    if protocol_prefix == assertion_prefix {
        return Err(SamlError::Invalid(
            "protocol and assertion tag prefixes must differ".into(),
        ));
    }
    Ok(())
}

/// Replace `{key}` placeholders in `raw_xml`, omitting optional placeholders.
///
/// `Some(value)` is XML-escaped and inserted, including `Some(String::new())`.
/// Inserted text is not scanned for `{key}` tokens. `None` removes attributes
/// whose complete value is the placeholder, removes elements whose complete
/// body is the placeholder, and renders any remaining occurrences as an empty
/// string. Those removals read the markup of `raw_xml` as written, before any
/// value is inserted. The first entry for a key wins.
///
/// Returns [`SamlError::Xml`] when the tags or attributes of `raw_xml` cannot
/// be read.
pub fn replace_tags_by_optional_value(
    raw_xml: &str,
    tags: &[(&str, Option<String>)],
) -> Result<String, SamlError> {
    let value_of = |key: &str| {
        tags.iter()
            .find(|(tag, _)| *tag == key)
            .map(|(_, value)| value.as_deref())
    };
    let absent = |raw: &str| {
        raw.strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
            .and_then(value_of)
            == Some(None)
    };
    let xml = omit_absent_markup(raw_xml, absent)?;
    Ok(substitute_placeholders(&xml, |key| {
        value_of(key).map(Option::unwrap_or_default)
    }))
}

fn substitute_placeholders<'v>(raw_xml: &str, lookup: impl Fn(&str) -> Option<&'v str>) -> String {
    let mut result = String::with_capacity(raw_xml.len());
    let mut rest = raw_xml;
    while let Some(open) = rest.find('{') {
        result.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let value = after_open
            .find('}')
            .and_then(|close| Some((close, lookup(&after_open[..close])?)));
        match value {
            Some((close, value)) => {
                result.push_str(&xml_escape(value));
                rest = &after_open[close + 1..];
            }
            None => {
                result.push('{');
                rest = after_open;
            }
        }
    }
    result.push_str(rest);
    result
}

/// An element read so far as its start tag and at most one text node. Each
/// variant holds the output length before the start tag.
#[derive(Clone, Copy)]
enum OptionalElement {
    StartTag(usize),
    AbsentBody(usize),
}

/// `raw_xml` without the attributes whose raw value is `absent`, and without
/// the elements whose only content is one `absent` text node.
fn omit_absent_markup(raw_xml: &str, absent: impl Fn(&str) -> bool) -> Result<String, SamlError> {
    let mut output = String::with_capacity(raw_xml.len());
    // quick-xml skips one leading byte order mark and counts its positions
    // from the byte after it.
    let markup = match raw_xml.strip_prefix('\u{feff}') {
        Some(markup) => {
            output.push('\u{feff}');
            markup
        }
        None => raw_xml,
    };
    let mut reader = Reader::from_str(raw_xml);
    let mut element = None;
    loop {
        let start = position(&reader)?;
        let event = reader.read_event().map_err(xml_err)?;
        let source = &markup[start..position(&reader)?];
        element = match event {
            Event::Eof => return Ok(output),
            Event::Start(tag) => {
                let before = output.len();
                push_tag(&mut output, &tag, source, ">", &absent)?;
                Some(OptionalElement::StartTag(before))
            }
            Event::Empty(tag) => {
                push_tag(&mut output, &tag, source, "/>", &absent)?;
                None
            }
            Event::Text(_) => {
                output.push_str(source);
                match element {
                    Some(OptionalElement::StartTag(before)) if absent(source) => {
                        Some(OptionalElement::AbsentBody(before))
                    }
                    Some(OptionalElement::StartTag(_) | OptionalElement::AbsentBody(_)) | None => {
                        None
                    }
                }
            }
            Event::End(_) => {
                match element {
                    Some(OptionalElement::AbsentBody(before)) => output.truncate(before),
                    Some(OptionalElement::StartTag(_)) | None => output.push_str(source),
                }
                None
            }
            Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {
                output.push_str(source);
                None
            }
        };
    }
}

fn position(reader: &Reader<&[u8]>) -> Result<usize, SamlError> {
    usize::try_from(reader.buffer_position()).map_err(xml_err)
}

/// Write `tag`, read from `source`, without its `absent` attributes, closing
/// it with `close`.
fn push_tag(
    output: &mut String,
    tag: &BytesStart<'_>,
    source: &str,
    close: &str,
    absent: impl Fn(&str) -> bool,
) -> Result<(), SamlError> {
    let attributes = tag
        .attributes()
        .collect::<Result<Vec<_>, _>>()
        .map_err(xml_err)?;
    if !attributes.iter().any(|attribute| absent(&attribute.value)) {
        output.push_str(source);
        return Ok(());
    }
    output.push('<');
    output.push_str(tag.name().into_inner());
    for attribute in attributes
        .iter()
        .filter(|attribute| !absent(&attribute.value))
    {
        // quick-xml does not report the quote of a value. A raw XML attribute
        // value contains at most one kind of quote, the one that did not
        // delimit it.
        let quote = if attribute.value.contains('"') {
            '\''
        } else {
            '"'
        };
        output.push(' ');
        output.push_str(attribute.key.into_inner());
        output.push('=');
        output.push(quote);
        output.push_str(&attribute.value);
        output.push(quote);
    }
    output.push_str(close);
    Ok(())
}

/// A single `<Attribute>` to render in a login response.
#[derive(Debug, Clone)]
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn build_attribute_statement(
    attributes: &[LoginResponseAttribute],
    attribute_template: &str,
    attribute_statement_template: &str,
) -> String {
    let attrs: String = attributes
        .iter()
        .map(|a| {
            let value_placeholder = format!("{{{}}}", tagging("attr", &a.value_tag));
            let name = escape_literal_template_text(&a.name);
            let name_format = escape_literal_template_text(&a.name_format);
            let value_xmlns_xs =
                escape_literal_template_text(a.value_xmlns_xs.as_deref().unwrap_or(DEFAULT_XS));
            let value_xmlns_xsi =
                escape_literal_template_text(a.value_xmlns_xsi.as_deref().unwrap_or(DEFAULT_XSI));
            let value_xsi_type = escape_literal_template_text(&a.value_xsi_type);
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

#[cfg(test)]
fn escape_literal_template_text(value: &str) -> String {
    xml_escape(value).replace('{', "&#123;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_values_are_escaped_in_attributes_and_element_text(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<a X=\"{V}\">{T}</a>",
            &[
                ("V", Some("a\"b&c<d".to_string())),
                ("T", Some("<raw>&amp;".to_string())),
            ],
        )?;
        assert_eq!(
            rendered,
            "<a X=\"a&quot;b&amp;c&lt;d\">&lt;raw&gt;&amp;amp;</a>"
        );
        Ok(())
    }

    #[test]
    fn optional_none_removes_placeholder_attribute_but_keeps_visible_text(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered =
            replace_tags_by_optional_value("<a id=\"{Id}\">visible</a>", &[("Id", None)])?;
        assert_eq!(rendered, "<a>visible</a>");
        Ok(())
    }

    #[test]
    fn optional_none_removes_element_when_placeholder_is_only_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<root><a>{Body}</a><b>x</b></root>",
            &[("Body", None)],
        )?;
        assert_eq!(rendered, "<root><b>x</b></root>");
        Ok(())
    }

    #[test]
    fn optional_none_in_mixed_text_becomes_empty_string() -> Result<(), Box<dyn std::error::Error>>
    {
        let rendered = replace_tags_by_optional_value("<a>Hello {Name}</a>", &[("Name", None)])?;
        assert_eq!(rendered, "<a>Hello </a>");
        Ok(())
    }

    #[test]
    fn optional_empty_string_keeps_empty_attribute_value() -> Result<(), Box<dyn std::error::Error>>
    {
        let rendered = replace_tags_by_optional_value(
            "<a id=\"{Id}\">visible</a>",
            &[("Id", Some(String::new()))],
        )?;
        assert_eq!(rendered, "<a id=\"\">visible</a>");
        Ok(())
    }

    #[test]
    fn renders_full_authn_request() -> Result<(), Box<dyn std::error::Error>> {
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
        )?;
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        assert!(xml.contains("ID=\"_abc\""));
        assert!(xml.contains("Destination=\"https://idp.example.com/sso\""));
        assert!(xml.contains("ForceAuthn=\"true\""));
        assert!(xml.contains("<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>"));
        assert!(!xml.contains("AssertionConsumerServiceIndex="));
        assert!(!xml.contains('{'));
        Ok(())
    }

    #[test]
    fn builds_attribute_statement_with_value_placeholder() {
        let attrs = [LoginResponseAttribute {
            name: "email".into(),
            value_tag: "user.email".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }];
        let expected = "<saml:AttributeStatement><saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">{attrUserEmail}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>";
        assert_eq!(
            build_attribute_statement(&attrs, ATTRIBUTE_TEMPLATE, ATTRIBUTE_STATEMENT_TEMPLATE),
            expected
        );
    }

    #[test]
    fn builds_attribute_statement_with_multiple_attributes() {
        let mk = |name: &str, tag: &str| LoginResponseAttribute {
            name: name.into(),
            value_tag: tag.into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        };
        let attrs = [mk("email", "user.email"), mk("firstname", "user.firstname")];
        let expected = "<saml:AttributeStatement><saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">{attrUserEmail}</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"firstname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">{attrUserFirstname}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>";
        assert_eq!(
            build_attribute_statement(&attrs, ATTRIBUTE_TEMPLATE, ATTRIBUTE_STATEMENT_TEMPLATE),
            expected
        );
    }

    #[test]
    fn inserted_values_are_not_scanned_for_later_placeholders(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<n>{NameID}</n><a>{attrRole}</a><m>{attrMail}</m><r>{InResponseTo}</r>",
            &[
                ("NameID", Some("a<b>{InResponseTo}".to_string())),
                ("attrRole", Some("admin-{attrMail}".to_string())),
                ("attrMail", Some("user".to_string())),
                ("InResponseTo", Some("_req".to_string())),
            ],
        )?;
        assert_eq!(
            rendered,
            "<n>a&lt;b&gt;{InResponseTo}</n><a>admin-{attrMail}</a><m>user</m><r>_req</r>"
        );
        Ok(())
    }

    #[test]
    fn optional_inserted_values_are_not_scanned_for_later_placeholders(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<root><n>{NameID}</n><s>{SessionIndex}</s></root>",
            &[
                ("NameID", Some("{SessionIndex}".to_string())),
                ("SessionIndex", Some("abc".to_string())),
            ],
        )?;
        assert_eq!(rendered, "<root><n>{SessionIndex}</n><s>abc</s></root>");
        Ok(())
    }

    #[test]
    fn logout_request_name_id_values_are_not_scanned_for_later_qualifiers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            concat!(
                r#"<LogoutRequest NotOnOrAfter="{NotOnOrAfter}">"#,
                r#"<NameID Format="{NameIDFormat}" NameQualifier="{NameQualifier}" "#,
                r#"SPNameQualifier="{SPNameQualifier}" SPProvidedID="{SPProvidedID}">"#,
                "{NameID}</NameID><SessionIndex>{SessionIndex}</SessionIndex>",
                "</LogoutRequest>",
            ),
            &[
                ("NameIDFormat", None),
                (
                    "NameID",
                    Some(
                        "{NameQualifier} & {SPNameQualifier} {SPProvidedID} {SessionIndex} {NotOnOrAfter}"
                            .to_string(),
                    ),
                ),
                ("NameQualifier", Some("https://idp.example.com".to_string())),
                ("SPNameQualifier", None),
                ("SPProvidedID", Some("{SessionIndex}".to_string())),
                ("SessionIndex", Some("idx-1".to_string())),
                ("NotOnOrAfter", Some("2020-01-01T00:00:00Z".to_string())),
            ],
        )?;
        assert_eq!(
            rendered,
            concat!(
                r#"<LogoutRequest NotOnOrAfter="2020-01-01T00:00:00Z">"#,
                r#"<NameID NameQualifier="https://idp.example.com" SPProvidedID="{SessionIndex}">"#,
                "{NameQualifier} &amp; {SPNameQualifier} {SPProvidedID} {SessionIndex} {NotOnOrAfter}",
                "</NameID><SessionIndex>idx-1</SessionIndex>",
                "</LogoutRequest>",
            )
        );
        Ok(())
    }

    #[test]
    fn optional_none_still_drops_an_element_after_a_value_containing_its_placeholder(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<root><n>{NameID}</n><s>{SessionIndex}</s></root>",
            &[
                ("NameID", Some("{SessionIndex}".to_string())),
                ("SessionIndex", None),
            ],
        )?;
        assert_eq!(rendered, "<root><n>{SessionIndex}</n></root>");
        Ok(())
    }

    #[test]
    fn optional_first_entry_for_a_repeated_key_wins() -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(
            "<a x=\"{K}\"/><b y=\"{L}\"/>",
            &[
                ("K", Some("v".to_string())),
                ("K", None),
                ("L", None),
                ("L", Some("w".to_string())),
            ],
        )?;
        assert_eq!(rendered, "<a x=\"v\"/><b/>");
        Ok(())
    }

    #[test]
    fn optional_none_keeps_attribute_syntax_inside_another_attribute_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(r#"<a title='x="{Id}"'/>"#, &[("Id", None)])?;
        assert_eq!(rendered, r#"<a title='x=""'/>"#);
        Ok(())
    }

    #[test]
    fn optional_none_keeps_attribute_syntax_in_element_text(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value(r#"<p>x="{Id}"</p>"#, &[("Id", None)])?;
        assert_eq!(rendered, r#"<p>x=""</p>"#);
        Ok(())
    }

    #[test]
    fn optional_none_keeps_an_element_whose_body_also_holds_a_comment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered = replace_tags_by_optional_value("<b><!-- <b> -->{X}</b>", &[("X", None)])?;
        assert_eq!(rendered, "<b><!-- <b> --></b>");
        Ok(())
    }

    #[test]
    fn optional_none_keeps_the_quotes_of_the_remaining_attributes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered =
            replace_tags_by_optional_value(r#"<a x='say "hi"' y="{Y}"/>"#, &[("Y", None)])?;
        assert_eq!(rendered, r#"<a x='say "hi"'/>"#);
        Ok(())
    }

    #[test]
    fn optional_none_reads_the_markup_after_a_byte_order_mark(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rendered =
            replace_tags_by_optional_value("\u{feff}<a x=\"{X}\">v</a>", &[("X", None)])?;
        assert_eq!(rendered, "\u{feff}<a>v</a>");
        let rendered =
            replace_tags_by_optional_value("\u{feff}\u{feff}<a x=\"{X}\">v</a>", &[("X", None)])?;
        assert_eq!(rendered, "\u{feff}\u{feff}<a>v</a>");
        Ok(())
    }

    #[test]
    fn template_that_is_not_well_formed_is_an_xml_error() {
        let rendered = replace_tags_by_optional_value("<a {X}/>", &[("X", None)]);
        assert!(
            matches!(rendered, Err(SamlError::Xml { .. })),
            "{rendered:?}"
        );
    }
}
