use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use crate::constants::namespace;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::protocol_element::SamlElement;
use crate::xml::{dom, extract_with_limits, ExtractorField, XmlLimits};

use super::description_read::EntityDescription;
use super::role::{self, SelectedDescriptors, SsoDescriptorRole};
use super::validity::ValidUntilBounds;
use super::{endpoints, entity_attributes, Metadata};

const MULTIPLE_ENTITY_DESCRIPTORS: &str = "metadata has more than one EntityDescriptor";

fn entity_descriptor_xml<'n>(
    xml: &str,
    roots: &'n [dom::Node],
    descriptor_starts: &HashSet<usize>,
) -> Result<(Range<usize>, Option<&'n dom::Node>), SamlError> {
    let [root] = roots else {
        return Ok((0..xml.len(), None));
    };
    if root.local_name != "EntitiesDescriptor" {
        return Ok((
            0..xml.len(),
            Some(root).filter(|root| root.local_name == "EntityDescriptor"),
        ));
    }
    let mut entities = Vec::new();
    collect_entity_descriptors(root, descriptor_starts, &mut entities);
    match entities.as_slice() {
        [entity] => Ok((entity.start..entity.end, Some(*entity))),
        [] => Err(SamlError::MissingMetadata("EntityDescriptor".into())),
        _ => Err(SamlError::xml(MULTIPLE_ENTITY_DESCRIPTORS)),
    }
}

fn role_xml(
    xml: &str,
    extraction: Range<usize>,
    entity: Option<&dom::Node>,
    descriptors: &[&dom::Node],
) -> String {
    let mut role_xml = String::with_capacity(extraction.len());
    let mut copied = extraction.start;
    let children = entity
        .map(|entity| entity.children.as_slice())
        .unwrap_or_default();
    for unread in children.iter().filter(|child| {
        role::is_sso_descriptor(child)
            && !descriptors
                .iter()
                .any(|descriptor| std::ptr::eq(*descriptor, *child))
    }) {
        role_xml.push_str(&xml[copied..unread.start]);
        copied = unread.end;
    }
    role_xml.push_str(&xml[copied..extraction.end]);
    role_xml
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

        let (extraction, entity) = entity_descriptor_xml(xml, &roots, &descriptor_starts)?;
        let descriptors = role.descriptors(xml, entity, limits)?;
        let source = role_xml(xml, extraction, entity, &descriptors.nodes);
        let meta = extract_name_id_formats(&source, limits)?;
        Ok(Self::from_extracted(
            Arc::from(xml),
            meta,
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
        let source = role_xml(
            entity_xml,
            0..entity_xml.len(),
            Some(&entity),
            &descriptors.nodes,
        );
        let meta = extract_name_id_formats(&source, limits)?;
        Ok(Self::from_extracted(
            Arc::clone(xml),
            meta,
            descriptors,
            EntityDescription::from_entity(member),
            entity_attributes::bound_attributes(path),
        ))
    }

    fn from_extracted(
        xml: Arc<str>,
        meta: Value,
        descriptors: SelectedDescriptors<'_>,
        description: EntityDescription,
        entity_attributes: Vec<SamlElement>,
    ) -> (Self, Vec<SamlElement>) {
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

fn extract_name_id_formats(source: &str, limits: XmlLimits) -> Result<Value, SamlError> {
    extract_with_limits(
        source,
        &[ExtractorField::new(
            "nameIDFormat",
            &["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
        )],
        limits,
    )
}
