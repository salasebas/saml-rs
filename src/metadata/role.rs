use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::dom::{self, XmlLimits};
use crate::xml::protocol_element::{self, SamlElement};
use crate::xml::xs_boolean;

use super::validity::ValidUntilBounds;
use super::KeyCertificates;

#[derive(Clone, Copy)]
pub(super) enum SsoDescriptorRole {
    Any,
    ServiceProvider,
    IdentityProvider,
}

pub(super) struct SelectedDescriptors {
    pub(super) namespaced: Vec<SamlElement>,
    pub(super) key_certificates: KeyCertificates,
    pub(super) entity_id: Option<String>,
    pub(super) valid_until_bounds: ValidUntilBounds,
    pub(super) signing_flags: SigningFlags,
    pub(super) scope_elements: Vec<SamlElement>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct SigningFlags {
    pub(super) authn_requests_signed: bool,
    pub(super) want_assertions_signed: bool,
    pub(super) want_authn_requests_signed: Option<bool>,
}

impl SsoDescriptorRole {
    pub(super) fn descriptors(
        self,
        xml: &str,
        entity: Option<&dom::Node>,
        limits: XmlLimits,
    ) -> Result<SelectedDescriptors, SamlError> {
        let local_name = match (self, entity) {
            (Self::Any, None) => return Ok(Self::no_descriptors()),
            (Self::Any, Some(_)) => "EntityDescriptor",
            (Self::ServiceProvider, _) => "SPSSODescriptor",
            (Self::IdentityProvider, _) => "IDPSSODescriptor",
        };
        let document = protocol_element::parse_saml_with_limits(xml, limits)?;
        let entity = entity.ok_or_else(|| SamlError::MissingMetadata(local_name.into()))?;
        let path = namespaced_path(&document, entity)?;
        let valid_until_bounds = match self {
            Self::Any => ValidUntilBounds::default(),
            Self::ServiceProvider | Self::IdentityProvider => ValidUntilBounds::from_path(&path),
        };
        let namespaced = path.last().ok_or_else(missing_entity)?;
        self.typed_descriptors(entity, namespaced, valid_until_bounds)
    }

    pub(super) fn typed_descriptors(
        self,
        entity: &dom::Node,
        namespaced: &SamlElement,
        mut valid_until_bounds: ValidUntilBounds,
    ) -> Result<SelectedDescriptors, SamlError> {
        let local_name = match self {
            Self::Any => return Ok(Self::untyped_descriptors(entity, namespaced)),
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        let is_metadata_entity = namespaced.is(namespace::METADATA, "EntityDescriptor");
        let entity_id = if is_metadata_entity {
            namespaced.attr("entityID").map(collapse_whitespace)
        } else {
            None
        };
        let mut scope_elements = Vec::new();
        if matches!(self, Self::IdentityProvider) && is_metadata_entity {
            scope_elements.extend(super::scope::scope_elements(namespaced).cloned());
        }
        let mut namespaced_descriptors = Vec::new();
        let mut signing_flags = SigningFlags::default();
        for descriptor in &namespaced.children {
            if descriptor.is(namespace::METADATA, local_name) && lists_saml2(descriptor) {
                match self {
                    Self::ServiceProvider => {
                        signing_flags.authn_requests_signed |=
                            signing_flag(descriptor, "AuthnRequestsSigned")?.unwrap_or_default();
                        signing_flags.want_assertions_signed |=
                            signing_flag(descriptor, "WantAssertionsSigned")?.unwrap_or_default();
                    }
                    Self::IdentityProvider => {
                        let want_authn_requests_signed =
                            signing_flag(descriptor, "WantAuthnRequestsSigned")?;
                        signing_flags.want_authn_requests_signed = signing_flags
                            .want_authn_requests_signed
                            .or(want_authn_requests_signed);
                        scope_elements.extend(super::scope::scope_elements(descriptor).cloned());
                    }
                    Self::Any => {}
                }
                namespaced_descriptors.push(descriptor);
                valid_until_bounds.push_role(descriptor);
            }
        }
        if namespaced_descriptors.is_empty() {
            return Err(SamlError::MissingMetadata(local_name.into()));
        }
        Ok(SelectedDescriptors {
            key_certificates: KeyCertificates::from_descriptors(&namespaced_descriptors),
            namespaced: namespaced_descriptors.into_iter().cloned().collect(),
            entity_id,
            valid_until_bounds,
            signing_flags,
            scope_elements,
        })
    }

    fn untyped_descriptors(entity: &dom::Node, namespaced: &SamlElement) -> SelectedDescriptors {
        let namespaced_descriptors: Vec<&SamlElement> = entity
            .children
            .iter()
            .zip(&namespaced.children)
            .filter(|(child, _)| is_sso_descriptor(child))
            .map(|(_, descriptor)| descriptor)
            .collect();
        SelectedDescriptors {
            key_certificates: KeyCertificates::from_descriptors(&namespaced_descriptors),
            namespaced: namespaced_descriptors.into_iter().cloned().collect(),
            entity_id: entity.attr("entityID").map(str::to_owned),
            valid_until_bounds: ValidUntilBounds::default(),
            signing_flags: SigningFlags::default(),
            scope_elements: Vec::new(),
        }
    }

    fn no_descriptors() -> SelectedDescriptors {
        SelectedDescriptors {
            namespaced: Vec::new(),
            key_certificates: KeyCertificates::default(),
            entity_id: None,
            valid_until_bounds: ValidUntilBounds::default(),
            signing_flags: SigningFlags::default(),
            scope_elements: Vec::new(),
        }
    }
}

fn signing_flag(descriptor: &SamlElement, name: &str) -> Result<Option<bool>, SamlError> {
    if descriptor.attr_ns(namespace::METADATA, name).is_some() {
        return Err(SamlError::Invalid(format!(
            "{} {name} must be unqualified",
            descriptor.local_name
        )));
    }
    descriptor
        .attr(name)
        .map(|value| {
            xs_boolean(Some(value)).ok_or_else(|| {
                SamlError::Invalid(format!(
                    "{} {name} must be an xs:boolean",
                    descriptor.local_name
                ))
            })
        })
        .transpose()
}

fn is_sso_descriptor(node: &dom::Node) -> bool {
    node.local_name.contains("SSODescriptor")
}

fn lists_saml2(descriptor: &SamlElement) -> bool {
    descriptor
        .attr("protocolSupportEnumeration")
        .is_some_and(|protocols| {
            protocols
                .split_ascii_whitespace()
                .any(|protocol| protocol == namespace::PROTOCOL)
        })
}

pub(super) fn namespaced_path<'a>(
    mut element: &'a SamlElement,
    entity: &dom::Node,
) -> Result<Vec<&'a SamlElement>, SamlError> {
    let mut path = Vec::new();
    loop {
        path.push(element);
        if element.start == entity.start && element.end == entity.end {
            return Ok(path);
        }
        element = element
            .children
            .iter()
            .find(|child| child.start <= entity.start && entity.end <= child.end)
            .ok_or_else(missing_entity)?;
    }
}

pub(super) fn missing_entity() -> SamlError {
    SamlError::xml("EntityDescriptor is not in the document")
}
