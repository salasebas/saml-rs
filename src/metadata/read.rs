use std::collections::HashSet;
use std::sync::Arc;

use crate::constants::namespace;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::protocol_element::SamlElement;
use crate::xml::{dom, XmlLimits};

use super::description_read::EntityDescription;
use super::role::{self, SelectedDescriptors, SsoDescriptorRole};
use super::validity::ValidUntilBounds;
use super::{endpoints, entity_attributes, Metadata};

const MULTIPLE_ENTITY_DESCRIPTORS: &str = "metadata has more than one EntityDescriptor";

fn entity_descriptor<'n>(
    roots: &'n [dom::Node],
    descriptor_starts: &HashSet<usize>,
) -> Result<Option<&'n dom::Node>, SamlError> {
    let root = match roots {
        [root] => root,
        [] => return Err(SamlError::xml("no document element")),
        _ => return Err(SamlError::xml("multiple document elements")),
    };
    if root.local_name != "EntitiesDescriptor" {
        return Ok(Some(root).filter(|root| root.local_name == "EntityDescriptor"));
    }
    let mut entities = Vec::new();
    collect_entity_descriptors(root, descriptor_starts, &mut entities);
    match entities.as_slice() {
        [entity] => Ok(Some(*entity)),
        [] => Err(SamlError::MissingMetadata("EntityDescriptor".into())),
        _ => Err(SamlError::xml(MULTIPLE_ENTITY_DESCRIPTORS)),
    }
}

fn collect_entity_descriptors<'a>(
    node: &'a dom::Node,
    descriptor_starts: &HashSet<usize>,
    found: &mut Vec<&'a dom::Node>,
) {
    if !descriptor_starts.contains(&node.start) {
        return;
    }
    if node.local_name == "EntityDescriptor" {
        found.push(node);
    } else {
        for child in &node.children {
            collect_entity_descriptors(child, descriptor_starts, found);
        }
    }
}

impl Metadata {
    pub(super) fn parse_role_with_policy(
        xml: &str,
        role: SsoDescriptorRole,
        policy: &crate::XmlPolicy,
    ) -> Result<(Self, Vec<SamlElement>), SamlError> {
        let limits = policy.limits;
        let mut descriptor_starts = HashSet::new();
        let roots = dom::parse_roots_with_element_names(xml, limits, |start, ns, name| {
            if ns == Some(namespace::METADATA)
                && matches!(name, "EntitiesDescriptor" | "EntityDescriptor")
            {
                descriptor_starts.insert(start);
            }
        })?;
        crate::schema::validate(xml, policy.schema_validator)?;
        if roots
            .iter()
            .filter(|n| n.local_name == "EntityDescriptor")
            .count()
            > 1
        {
            return Err(SamlError::xml(MULTIPLE_ENTITY_DESCRIPTORS));
        }

        let entity = entity_descriptor(&roots, &descriptor_starts)?;
        let descriptors = role.descriptors(xml, entity, limits)?;
        Ok(Self::from_descriptors(
            Arc::from(xml),
            descriptors,
            EntityDescription::read(xml, entity, limits)?,
            entity_attributes::read_bound_attributes(xml, &roots, entity, limits)?,
        ))
    }

    pub(super) fn from_aggregate_entity(
        xml: &Arc<str>,
        path: &[&SamlElement],
        role: SsoDescriptorRole,
        limits: XmlLimits,
    ) -> Result<(Self, Vec<SamlElement>), SamlError> {
        let member = path.last().ok_or_else(role::missing_entity)?;
        let entity_xml = &xml[member.start..member.end];
        let entity = dom::parse_fragment_with_limits(entity_xml, limits)?.root;
        let descriptors =
            role.typed_descriptors(&entity, member, ValidUntilBounds::from_path(path))?;
        Ok(Self::from_descriptors(
            Arc::clone(xml),
            descriptors,
            EntityDescription::from_entity(member),
            entity_attributes::bound_attributes(path),
        ))
    }

    fn from_descriptors(
        xml: Arc<str>,
        descriptors: SelectedDescriptors,
        description: EntityDescription,
        entity_attributes: Vec<SamlElement>,
    ) -> (Self, Vec<SamlElement>) {
        let mut meta = Value::Object(Vec::new());
        meta.insert(
            "nameIDFormat",
            Value::Array(
                descriptors
                    .namespaced
                    .iter()
                    .flat_map(|descriptor| &descriptor.children)
                    .filter(|child| child.is(namespace::METADATA, "NameIDFormat"))
                    .map(|format| Value::Str(format.text.clone()))
                    .collect(),
            ),
        );
        let role_services = |name| {
            descriptors
                .namespaced
                .iter()
                .map(|role| {
                    endpoints::role_endpoints(
                        role,
                        name,
                        &["Binding", "Location", "ResponseLocation"],
                    )
                })
                .collect()
        };
        let metadata = Self {
            xml,
            meta,
            entity_id: descriptors.entity_id,
            key_certificates: descriptors.key_certificates,
            single_logout_service_roles: role_services("SingleLogoutService"),
            manage_name_id_service_roles: role_services("ManageNameIDService"),
            valid_until_bounds: descriptors.valid_until_bounds,
            signing_flags: descriptors.signing_flags,
            scope_elements: descriptors.scope_elements,
            description,
            entity_attributes,
        };
        (metadata, descriptors.namespaced)
    }
}
