//! Entity-level organization and contact metadata.

use crate::error::SamlError;
use crate::xml::any_uri::is_absolute_uri_reference;
use crate::xml::is_xml_char;

use super::write::MetadataWriter;

pub(super) const REFEDS_NAMESPACE: &str = "http://refeds.org/metadata";
pub(super) const SECURITY_CONTACT: &str = "http://refeds.org/metadata/contactType/security";

/// A metadata value qualified by an XML Schema language tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedValue {
    /// `xml:lang`, for example `en` or `es-MX`.
    pub lang: String,
    /// Display text or a URI, depending on the containing element.
    pub value: String,
}

impl LocalizedValue {
    /// Create a localized value. Generation validates the language tag.
    pub fn new(lang: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            lang: lang.into(),
            value: value.into(),
        }
    }
}

/// Organization responsible for an entity.
///
/// Generation requires at least one entry in each list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Organization {
    /// `OrganizationName` values, in order.
    pub names: Vec<LocalizedValue>,
    /// `OrganizationDisplayName` values, in order.
    pub display_names: Vec<LocalizedValue>,
    /// `OrganizationURL` values, in order. Each URI must be absolute.
    pub urls: Vec<LocalizedValue>,
}

/// Responsibility of a metadata contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactType {
    /// Technical contact.
    Technical,
    /// Support contact.
    Support,
    /// Administrative contact.
    Administrative,
    /// Billing contact.
    Billing,
    /// Other contact.
    Other,
    /// REFEDS security contact, written as `other` with `remd:contactType`.
    ///
    /// This publishes the extension only; it does not assert Sirtfi compliance.
    Security,
}

impl ContactType {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Support => "support",
            Self::Administrative => "administrative",
            Self::Billing => "billing",
            Self::Other | Self::Security => "other",
        }
    }
}

/// Contact responsible for an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPerson {
    /// Contact responsibility, including the REFEDS security extension.
    pub contact_type: ContactType,
    /// Optional company name.
    pub company: Option<String>,
    /// Optional given name.
    pub given_name: Option<String>,
    /// Optional surname (`SurName`).
    pub surname: Option<String>,
    /// Email addresses as `mailto:` URIs, in order.
    pub email_addresses: Vec<String>,
    /// Telephone numbers, in order.
    pub telephone_numbers: Vec<String>,
}

impl ContactPerson {
    /// Create a contact with no optional details.
    pub fn new(contact_type: ContactType) -> Self {
        Self {
            contact_type,
            company: None,
            given_name: None,
            surname: None,
            email_addresses: Vec::new(),
            telephone_numbers: Vec::new(),
        }
    }
}

pub(crate) fn validate_description(
    organization: Option<&Organization>,
    contacts: &[ContactPerson],
    error_url: Option<&str>,
) -> Result<(), SamlError> {
    if let Some(organization) = organization {
        for (name, values) in [
            ("OrganizationName", &organization.names),
            ("OrganizationDisplayName", &organization.display_names),
            ("OrganizationURL", &organization.urls),
        ] {
            if values.is_empty() {
                return Err(SamlError::Invalid(format!("Organization requires {name}")));
            }
            for value in values {
                if !is_language_tag(&value.lang) {
                    return Err(SamlError::Invalid(format!("invalid xml:lang on {name}")));
                }
                validate_text(&value.value)?;
                if name == "OrganizationURL" && !is_absolute_uri_reference(&value.value) {
                    return Err(SamlError::Invalid(
                        "OrganizationURL must be an absolute URI reference".into(),
                    ));
                }
            }
        }
    }
    for contact in contacts {
        for text in contact
            .company
            .iter()
            .chain(&contact.given_name)
            .chain(&contact.surname)
            .chain(&contact.telephone_numbers)
        {
            validate_text(text)?;
        }
        for email in &contact.email_addresses {
            if !is_absolute_uri_reference(email)
                || !email
                    .split_once(':')
                    .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("mailto"))
                || email.contains('#')
            {
                return Err(SamlError::Invalid(
                    "EmailAddress must be a mailto: URI".into(),
                ));
            }
        }
    }
    if error_url.is_some_and(|url| !is_absolute_uri_reference(url)) {
        return Err(SamlError::Invalid(
            "errorURL must be an absolute URI reference".into(),
        ));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), SamlError> {
    if !value.chars().all(is_xml_char) {
        return Err(SamlError::Invalid(
            "metadata description contains a character XML cannot represent".into(),
        ));
    }
    Ok(())
}

fn is_language_tag(value: &str) -> bool {
    let mut parts = value.split('-');
    parts.next().is_some_and(|first| {
        (1..=8).contains(&first.len()) && first.bytes().all(|byte| byte.is_ascii_alphabetic())
    }) && parts.all(|part| {
        (1..=8).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

pub(super) fn write_description(
    writer: &mut MetadataWriter,
    organization: Option<&Organization>,
    contacts: &[ContactPerson],
) {
    if let Some(organization) = organization {
        writer.start("Organization", &[]);
        for (name, values) in [
            ("OrganizationName", &organization.names),
            ("OrganizationDisplayName", &organization.display_names),
            ("OrganizationURL", &organization.urls),
        ] {
            for value in values {
                writer.text_element_with_attrs(name, &[("xml:lang", &value.lang)], &value.value);
            }
        }
        writer.end("Organization");
    }
    for contact in contacts {
        let mut attrs = vec![("contactType", contact.contact_type.as_str())];
        if contact.contact_type == ContactType::Security {
            attrs.extend([
                ("xmlns:remd", REFEDS_NAMESPACE),
                ("remd:contactType", SECURITY_CONTACT),
            ]);
        }
        writer.start("ContactPerson", &attrs);
        for (name, value) in [
            ("Company", &contact.company),
            ("GivenName", &contact.given_name),
            ("SurName", &contact.surname),
        ] {
            if let Some(value) = value {
                writer.text_element(name, value);
            }
        }
        for email in &contact.email_addresses {
            writer.text_element("EmailAddress", email);
        }
        for phone in &contact.telephone_numbers {
            writer.text_element("TelephoneNumber", phone);
        }
        writer.end("ContactPerson");
    }
}
