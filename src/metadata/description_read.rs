use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{Node, XmlLimits};
use crate::xml::protocol_element::{parse_saml_with_limits, SamlElement};

use super::description::{
    ContactPerson, ContactType, LocalizedValue, Organization, REFEDS_NAMESPACE, SECURITY_CONTACT,
};

#[derive(Debug, Clone, Default)]
pub(super) struct EntityDescription {
    organizations: Vec<SamlElement>,
    contacts: Vec<SamlElement>,
}

impl EntityDescription {
    pub(super) fn read(
        xml: &str,
        entity: Option<&Node>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let Some(entity) = entity else {
            return Ok(Self::default());
        };
        if !entity
            .children
            .iter()
            .any(|child| matches!(child.local_name.as_str(), "Organization" | "ContactPerson"))
        {
            return Ok(Self::default());
        }
        let element =
            super::role::namespaced_element(parse_saml_with_limits(xml, limits)?, entity)?;
        if !element.is(namespace::METADATA, "EntityDescriptor") {
            return Ok(Self::default());
        }
        let mut description = Self::default();
        for child in element.children {
            if child.is(namespace::METADATA, "Organization") {
                description.organizations.push(child);
            } else if child.is(namespace::METADATA, "ContactPerson") {
                description.contacts.push(child);
            }
        }
        Ok(description)
    }

    pub(super) fn organization(&self) -> Result<Option<Organization>, SamlError> {
        let element = match self.organizations.as_slice() {
            [] => return Ok(None),
            [element] => element,
            _ => {
                return Err(SamlError::Invalid(
                    "multiple entity-level Organizations".into(),
                ))
            }
        };
        let localized = |name| {
            children(element, name)
                .map(|child| {
                    let lang = child
                        .attr_ns("http://www.w3.org/XML/1998/namespace", "lang")
                        .ok_or_else(|| SamlError::Invalid(format!("{name} is missing xml:lang")))?;
                    Ok(LocalizedValue::new(lang, &child.text))
                })
                .collect::<Result<Vec<_>, SamlError>>()
        };
        Ok(Some(Organization {
            names: localized("OrganizationName")?,
            display_names: localized("OrganizationDisplayName")?,
            urls: localized("OrganizationURL")?,
        }))
    }

    pub(super) fn contacts(&self) -> Result<Vec<ContactPerson>, SamlError> {
        self.contacts
            .iter()
            .map(|element| {
                let contact_type = match element.attr("contactType") {
                    Some("technical") => ContactType::Technical,
                    Some("support") => ContactType::Support,
                    Some("administrative") => ContactType::Administrative,
                    Some("billing") => ContactType::Billing,
                    Some("other")
                        if element.attr_ns(REFEDS_NAMESPACE, "contactType")
                            == Some(SECURITY_CONTACT) =>
                    {
                        ContactType::Security
                    }
                    Some("other") => ContactType::Other,
                    _ => {
                        return Err(SamlError::Invalid(
                            "missing or unknown ContactPerson contactType".into(),
                        ))
                    }
                };
                Ok(ContactPerson {
                    contact_type,
                    company: children(element, "Company")
                        .next()
                        .map(|child| child.text.clone()),
                    given_name: children(element, "GivenName")
                        .next()
                        .map(|child| child.text.clone()),
                    surname: children(element, "SurName")
                        .next()
                        .map(|child| child.text.clone()),
                    email_addresses: children(element, "EmailAddress")
                        .map(|child| child.text.clone())
                        .collect(),
                    telephone_numbers: children(element, "TelephoneNumber")
                        .map(|child| child.text.clone())
                        .collect(),
                })
            })
            .collect()
    }
}

fn children<'a>(element: &'a SamlElement, name: &'a str) -> impl Iterator<Item = &'a SamlElement> {
    element
        .children
        .iter()
        .filter(move |child| child.is(namespace::METADATA, name))
}
