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
    ) -> Result<Vec<&'a dom::Node>, SamlError> {
        let local_name = match self {
            Self::Any => {
                return Ok(entity
                    .into_iter()
                    .flat_map(|entity| &entity.children)
                    .filter(|child| is_sso_descriptor(child))
                    .collect())
            }
            Self::ServiceProvider => "SPSSODescriptor",
            Self::IdentityProvider => "IDPSSODescriptor",
        };
        let selected: Vec<&dom::Node> = match entity {
            Some(entity) => {
                let namespaced = namespaced_element(xml, entity, limits)?;
                entity
                    .children
                    .iter()
                    .zip(&namespaced.children)
                    .filter(|(_, descriptor)| {
                        descriptor.is(namespace::METADATA, local_name) && lists_saml2(descriptor)
                    })
                    .map(|(child, _)| child)
                    .collect()
            }
            None => Vec::new(),
        };
        if selected.is_empty() {
            return Err(SamlError::MissingMetadata(local_name.into()));
        }
        Ok(selected)
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

fn namespaced_element(
    xml: &str,
    entity: &dom::Node,
    limits: XmlLimits,
) -> Result<SamlElement, SamlError> {
    let mut element = protocol_element::parse_saml_with_limits(xml, limits)?;
    while element.span != (entity.start..entity.end) {
        let child = element
            .children
            .into_iter()
            .find(|child| child.span.start <= entity.start && entity.end <= child.span.end)
            .ok_or_else(|| SamlError::Xml("EntityDescriptor is not in the document".into()))?;
        element = child;
    }
    Ok(element)
}
