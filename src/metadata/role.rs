use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{self, XmlLimits};
use crate::xml::protocol_element::{self, SamlElement};
use crate::xml::{xs_boolean, ExtractorField};

#[derive(Clone, Copy)]
pub(super) enum SsoDescriptorRole {
    Any,
    ServiceProvider,
    IdentityProvider,
}

pub(super) struct SelectedDescriptors<'a> {
    pub(super) nodes: Vec<&'a dom::Node>,
    pub(super) valid_until_bounds: Vec<String>,
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
    pub(super) fn fields(self) -> Vec<ExtractorField> {
        let descriptor = match self {
            Self::Any => "~SSODescriptor",
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        vec![ExtractorField::new(
            "singleLogoutService",
            &["EntityDescriptor", descriptor, "SingleLogoutService"],
        )
        .capture_source()]
    }

    pub(super) fn descriptors<'a>(
        self,
        xml: &str,
        entity: Option<&'a dom::Node>,
        limits: XmlLimits,
    ) -> Result<SelectedDescriptors<'a>, SamlError> {
        let local_name = match self {
            Self::Any => {
                return Ok(SelectedDescriptors {
                    nodes: entity
                        .into_iter()
                        .flat_map(|entity| &entity.children)
                        .filter(|child| is_sso_descriptor(child))
                        .collect(),
                    valid_until_bounds: Vec::new(),
                    signing_flags: SigningFlags::default(),
                    scope_elements: Vec::new(),
                })
            }
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        let document = protocol_element::parse_saml_with_limits(xml, limits)?;
        let entity = entity.ok_or_else(|| SamlError::MissingMetadata(local_name.into()))?;
        let (namespaced, mut valid_until_bounds) = namespaced_entity(document, entity)?;
        let mut scope_elements = Vec::new();
        if matches!(self, Self::IdentityProvider)
            && namespaced.is(namespace::METADATA, "EntityDescriptor")
        {
            scope_elements.extend(super::scope::scope_elements(&namespaced).cloned());
        }
        let mut nodes = Vec::new();
        let mut signing_flags = SigningFlags::default();
        for (child, descriptor) in entity.children.iter().zip(namespaced.children) {
            if descriptor.is(namespace::METADATA, local_name) && lists_saml2(&descriptor) {
                match self {
                    Self::ServiceProvider => {
                        signing_flags.authn_requests_signed |=
                            signing_flag(&descriptor, "AuthnRequestsSigned")?.unwrap_or_default();
                        signing_flags.want_assertions_signed |=
                            signing_flag(&descriptor, "WantAssertionsSigned")?.unwrap_or_default();
                    }
                    Self::IdentityProvider => {
                        let want_authn_requests_signed =
                            signing_flag(&descriptor, "WantAuthnRequestsSigned")?;
                        signing_flags.want_authn_requests_signed = signing_flags
                            .want_authn_requests_signed
                            .or(want_authn_requests_signed);
                        scope_elements.extend(super::scope::scope_elements(&descriptor).cloned());
                    }
                    Self::Any => {}
                }
                nodes.push(child);
                valid_until_bounds.extend(descriptor.attr("validUntil").map(str::to_owned));
            }
        }
        if nodes.is_empty() {
            return Err(SamlError::MissingMetadata(local_name.into()));
        }
        Ok(SelectedDescriptors {
            nodes,
            valid_until_bounds,
            signing_flags,
            scope_elements,
        })
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

pub(super) fn is_sso_descriptor(node: &dom::Node) -> bool {
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

pub(super) fn namespaced_entity(
    mut element: SamlElement,
    entity: &dom::Node,
) -> Result<(SamlElement, Vec<String>), SamlError> {
    let mut bounds = Vec::new();
    loop {
        if matches!(
            element.local_name.as_str(),
            "EntitiesDescriptor" | "EntityDescriptor"
        ) {
            bounds.extend(element.attr("validUntil").map(str::to_owned));
        }
        if element.start == entity.start && element.end == entity.end {
            return Ok((element, bounds));
        }
        let child = element
            .children
            .into_iter()
            .find(|child| child.start <= entity.start && entity.end <= child.end)
            .ok_or_else(|| SamlError::xml("EntityDescriptor is not in the document"))?;
        element = child;
    }
}
