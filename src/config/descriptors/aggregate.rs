use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::constants::namespace;
use crate::metadata::RootValidUntil;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::protocol_element::{parse_saml_with_limits, SamlElement};

use super::{
    ensure_metadata_trust, AppliedMetadataTrust, EntityId, IdpDescriptor, IdpMetadata,
    ImportedMetadata, MetadataTrustPolicy, SamlError, SpDescriptor, SpMetadata, XmlLimits,
};

/// Federation metadata loaded once for repeated peer lookups by entity ID.
///
/// Lookups use the trust policy applied at import. A descriptor carries the
/// earliest `validUntil` on its SAML 2.0 roles, entity, and enclosing groups.
/// Each descriptor shares the original aggregate XML and, when verified,
/// the signed root XML with the aggregate.
///
/// ```no_run
/// use saml_rs::{CertificatePem, EntityId, MetadataAggregate, MetadataTrustPolicy, XmlLimits};
///
/// # fn run(xml: &str, federation_certificate: CertificatePem) -> Result<(), saml_rs::SamlError> {
/// let mut limits = XmlLimits::default();
/// limits.max_bytes = 64 * 1024 * 1024;
/// limits.max_elements = 500_000;
/// let aggregate = MetadataAggregate::from_xml(
///     xml,
///     MetadataTrustPolicy::RequireSignature {
///         trusted_certificates: &[federation_certificate],
///     },
///     limits,
/// )?;
/// let idp = aggregate.idp_descriptor(&EntityId::try_new("https://idp.example.com/metadata")?)?;
/// let sp = aggregate.sp_descriptor(&EntityId::try_new("https://sp.example.com/metadata")?)?;
/// # let _ = (idp, sp);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MetadataAggregate {
    xml: Arc<str>,
    root: SamlElement,
    entities: HashMap<String, EntityMatch>,
    trust: AppliedMetadataTrust,
    limits: XmlLimits,
}

#[derive(Debug)]
enum EntityMatch {
    Unique(Vec<usize>),
    Duplicate,
}

impl MetadataAggregate {
    /// Load an `md:EntitiesDescriptor` and index its members with explicit XML limits.
    ///
    /// Signature-requiring policies verify the aggregate root against caller-pinned
    /// certificates once. Select [`MetadataTrustPolicy::Unverified`] to accept an
    /// externally authenticated document without checking its signature.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] for malformed XML, an exceeded resource limit, a
    /// root other than `md:EntitiesDescriptor`, or an unsatisfied trust policy.
    pub fn from_xml(
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let root = parse_saml_with_limits(xml, limits)?;
        if !root.is(namespace::METADATA, "EntitiesDescriptor") {
            return Err(SamlError::MissingMetadata("EntitiesDescriptor".into()));
        }
        let trust = ensure_metadata_trust(xml, trust, limits)?;
        let mut entities = HashMap::new();
        index_members(&root, &mut Vec::new(), &mut entities);
        Ok(Self {
            xml: Arc::from(xml),
            root,
            entities,
            trust,
            limits,
        })
    }

    /// Refuse the aggregate unless its root `EntitiesDescriptor` carries a
    /// `validUntil` at most `max_validity` after `now`.
    ///
    /// A `validUntil` below the root does not satisfy the requirement. Call this right after [`Self::from_xml`], with the
    /// time that the import is accepted at.
    ///
    /// The check does not refuse a root `validUntil` that has already been
    /// reached; typed flows refuse descriptors looked up here from that
    /// instant.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MetadataRootValidUntilRefused`] when the root has no
    /// `validUntil` or it lies more than `max_validity` after `now`.
    /// Returns [`SamlError::TimeWindowInvalid`] when the root `validUntil` is
    /// not an `xs:dateTime` with a timezone, and [`SamlError::Invalid`] when
    /// `now` is outside the supported SAML time range.
    pub fn require_root_valid_until(
        self,
        now: SystemTime,
        max_validity: Duration,
    ) -> Result<Self, SamlError> {
        RootValidUntil::parse(self.root.attr("validUntil"))?.ensure_within(now, max_validity)?;
        Ok(self)
    }

    /// Import the named entity's SAML 2.0 identity provider roles.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MetadataEntityNotFound`] or [`SamlError::DuplicateMetadataEntity`]
    /// if the entity ID has zero or several matches after XML Schema whitespace
    /// collapse. Returns an error if the selected entity lacks a SAML 2.0 IdP
    /// role or its metadata is invalid.
    pub fn idp_descriptor(&self, entity_id: &EntityId) -> Result<IdpDescriptor, SamlError> {
        let path = self.entity_path(entity_id)?;
        let metadata = IdpMetadata::from_aggregate_entity(&self.xml, &path, self.limits)?;
        let imported = ImportedMetadata::new(
            entity_id.clone(),
            metadata.as_metadata(),
            self.trust.clone(),
        )?;
        Ok(IdpDescriptor::from_import(metadata, imported))
    }

    /// Import the named entity's SAML 2.0 service provider roles.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MetadataEntityNotFound`] or [`SamlError::DuplicateMetadataEntity`]
    /// if the entity ID has zero or several matches after XML Schema whitespace
    /// collapse. Returns an error if the selected entity lacks a SAML 2.0 SP
    /// role or its metadata is invalid.
    pub fn sp_descriptor(&self, entity_id: &EntityId) -> Result<SpDescriptor, SamlError> {
        let path = self.entity_path(entity_id)?;
        let metadata = SpMetadata::from_aggregate_entity(&self.xml, &path, self.limits)?;
        let imported = ImportedMetadata::new(
            entity_id.clone(),
            metadata.as_metadata(),
            self.trust.clone(),
        )?;
        Ok(SpDescriptor::from_import(metadata, imported))
    }

    fn entity_path(&self, entity_id: &EntityId) -> Result<Vec<&SamlElement>, SamlError> {
        let indices = match self.entities.get(entity_id.as_str()) {
            Some(EntityMatch::Unique(indices)) => indices,
            Some(EntityMatch::Duplicate) => {
                return Err(SamlError::DuplicateMetadataEntity {
                    entity_id: entity_id.clone(),
                });
            }
            None => {
                return Err(SamlError::MetadataEntityNotFound {
                    entity_id: entity_id.clone(),
                });
            }
        };
        let mut node = &self.root;
        let mut path = Vec::with_capacity(indices.len() + 1);
        path.push(node);
        for &index in indices {
            node = &node.children[index];
            path.push(node);
        }
        Ok(path)
    }
}

fn index_members(
    group: &SamlElement,
    path: &mut Vec<usize>,
    entities: &mut HashMap<String, EntityMatch>,
) {
    for (index, member) in group.children.iter().enumerate() {
        if member.namespace != namespace::METADATA {
            continue;
        }
        path.push(index);
        match member.local_name.as_str() {
            "EntitiesDescriptor" => index_members(member, path, entities),
            "EntityDescriptor" => {
                if let Some(entity_id) = member.attr("entityID") {
                    entities
                        .entry(collapse_whitespace(entity_id))
                        .and_modify(|entry| *entry = EntityMatch::Duplicate)
                        .or_insert_with(|| EntityMatch::Unique(path.clone()));
                }
            }
            _ => {}
        }
        path.pop();
    }
}
