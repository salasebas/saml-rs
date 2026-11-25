use crate::binding::xml_escape;
use crate::util::camel_case;

pub const ATTRIBUTE_STATEMENT_TEMPLATE: &str =
    "<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>";

pub const ATTRIBUTE_TEMPLATE: &str = "<saml:Attribute Name=\"{Name}\" NameFormat=\"{NameFormat}\"><saml:AttributeValue xmlns:xs=\"{ValueXmlnsXs}\" xmlns:xsi=\"{ValueXmlnsXsi}\" xsi:type=\"{ValueXsiType}\">{Value}</saml:AttributeValue></saml:Attribute>";

const DEFAULT_XS: &str = "http://www.w3.org/2001/XMLSchema";
const DEFAULT_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

pub const LOGIN_RESPONSE_TEMPLATE: &str = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status><saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{AssertionID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"{SubjectConfirmationDataNotOnOrAfter}\" Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{ConditionsNotBefore}\" NotOnOrAfter=\"{ConditionsNotOnOrAfter}\"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>";

pub(crate) const AUTHN_STATEMENT: &str = "<saml:AuthnStatement AuthnInstant=\"{IssueInstant}\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";

pub(crate) fn fill_template(raw_xml: &str, tags: &[(&str, String)]) -> String {
    let mut result = String::with_capacity(raw_xml.len());
    let mut rest = raw_xml;
    while let Some(open) = rest.find('{') {
        result.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let value = after_open.find('}').and_then(|close| {
            let key = &after_open[..close];
            let (_, value) = tags.iter().find(|(name, _)| *name == key)?;
            Some((close, value.as_str()))
        });
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

#[derive(Debug, Clone)]
pub struct LoginResponseAttribute {
    pub name: String,
    pub name_format: String,
    pub value_xsi_type: String,
    pub value_tag: String,
    pub value_xmlns_xs: Option<String>,
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

fn escape_literal_template_text(value: &str) -> String {
    xml_escape(value).replace('{', "&#123;")
}

mod tests {
    use super::*;

    #[test]
    fn replacement_values_are_escaped_in_attributes_and_element_text() {
        let rendered = fill_template(
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
    fn inserted_values_are_not_scanned_for_later_placeholders() {
        let rendered = fill_template(
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
}
