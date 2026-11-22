use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{self, XmlLimits};
use crate::xml::protocol_element::{self, SamlElement};
use crate::xml::ExtractorField;

#[derive(Clone, Copy)]
pub(super) enum SsoDescriptorRole {
    Any,
    ServiceProvider,
    IdentityProvider,
}

pub(super) struct SelectedDescriptors<'a> {
    pub(super) nodes: Vec<&'a dom::Node>,
    pub(super) valid_until_bounds: Vec<String>,
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
        .with_context()]
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
                })
            }
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        let document = protocol_element::parse_saml_with_limits(xml, limits)?;
        let entity = entity.ok_or_else(|| SamlError::MissingMetadata(local_name.into()))?;
        let (namespaced, mut valid_until_bounds) = namespaced_entity(document, entity)?;
        let mut nodes = Vec::new();
        for (child, descriptor) in entity.children.iter().zip(namespaced.children) {
            if descriptor.is(namespace::METADATA, local_name) && lists_saml2(&descriptor) {
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
        })
    }
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
        if element.span == (entity.start..entity.end) {
            return Ok((element, bounds));
        }
        let child = element
            .children
            .into_iter()
            .find(|child| child.span.start <= entity.start && entity.end <= child.span.end)
            .ok_or_else(|| SamlError::xml("EntityDescriptor is not in the document"))?;
        element = child;
    }
}
