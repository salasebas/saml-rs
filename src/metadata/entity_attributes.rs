use crate::constants::entity_attribute::{
    ASSURANCE_CERTIFICATION, ENTITY_CATEGORY, ENTITY_CATEGORY_SUPPORT, SUBJECT_ID_REQUIREMENT,
};
use crate::constants::namespace;
use crate::error::SamlError;
use crate::model::{Attribute, AttributeNameFormat, AttributeValue};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::dom::{Node, XmlLimits};
use crate::xml::is_xml_char;
use crate::xml::protocol_element::{parse_saml_with_limits, SamlElement};

use super::write::MetadataWriter;

const NAMESPACE: &str = "urn:oasis:names:tc:SAML:metadata:attribute";

/// The `saml:Attribute`s that metadata binds to an entity.
///
/// They come from the `mdattr:EntityAttributes` in the `Extensions` of the
/// entity's `EntityDescriptor` and of every enclosing `EntitiesDescriptor`, in
/// document order: the outermost group first and the entity last. A
/// `saml:Assertion` inside `mdattr:EntityAttributes` is not read.
///
/// Each [`AttributeValue`] is the direct text of its `saml:AttributeValue`,
/// as for the attributes of an assertion. Child elements of a value are not
/// read.
///
/// # Examples
///
/// ```
/// use saml_rs::metadata::SpMetadata;
/// use saml_rs::SubjectIdRequirement;
///
/// # fn main() -> Result<(), saml_rs::SamlError> {
/// let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
///     xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
///     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
///     entityID="https://sp.example.com/metadata">
///   <Extensions>
///     <mdattr:EntityAttributes>
///       <saml:Attribute Name="http://macedir.org/entity-category"
///           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
///         <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
///       </saml:Attribute>
///       <saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req"
///           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
///         <saml:AttributeValue>pairwise-id</saml:AttributeValue>
///       </saml:Attribute>
///     </mdattr:EntityAttributes>
///   </Extensions>
///   <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
///     <AssertionConsumerService index="0"
///         Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
///         Location="https://sp.example.com/acs"/>
///   </SPSSODescriptor>
/// </EntityDescriptor>"#;
///
/// let attributes = SpMetadata::from_xml(xml)?.as_metadata().entity_attributes()?;
/// assert!(attributes
///     .entity_categories()
///     .contains(&"http://refeds.org/category/research-and-scholarship"));
/// assert_eq!(
///     attributes.subject_id_requirement()?,
///     Some(SubjectIdRequirement::PairwiseId)
/// );
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntityAttributes(Vec<Attribute>);

impl EntityAttributes {
    /// Borrow the attributes as a slice.
    pub fn as_slice(&self) -> &[Attribute] {
        &self.0
    }

    /// Iterate over the attributes in order.
    pub fn iter(&self) -> std::slice::Iter<'_, Attribute> {
        self.0.iter()
    }

    /// Values of every `http://macedir.org/entity-category` attribute, in
    /// order: the categories the entity belongs to.
    ///
    /// Like [`Self::subject_id_requirement`], this reads an attribute with the
    /// URI `NameFormat`, the unspecified one, or none. Values compare as exact
    /// strings.
    pub fn entity_categories(&self) -> Vec<&str> {
        self.values(ENTITY_CATEGORY)
    }

    /// Values of every `http://macedir.org/entity-category-support` attribute,
    /// in order: the categories whose peers the entity supports.
    pub fn entity_category_support(&self) -> Vec<&str> {
        self.values(ENTITY_CATEGORY_SUPPORT)
    }

    /// Values of every
    /// `urn:oasis:names:tc:SAML:attribute:assurance-certification` attribute,
    /// in order: the assurance frameworks the entity is certified under.
    pub fn assurance_certifications(&self) -> Vec<&str> {
        self.values(ASSURANCE_CERTIFICATION)
    }

    /// The subject identifier the entity requires, read from its
    /// `urn:oasis:names:tc:SAML:profiles:subject-id:req` attributes.
    ///
    /// `None` when the entity publishes none.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when one of those attributes does not
    /// have exactly one value, a value is not one of the four the profile
    /// defines, or two attributes require different identifiers.
    pub fn subject_id_requirement(&self) -> Result<Option<SubjectIdRequirement>, SamlError> {
        let mut requirement = None;
        for attribute in self.named(SUBJECT_ID_REQUIREMENT) {
            let [value] = attribute.values() else {
                return Err(SamlError::Invalid(format!(
                    "{SUBJECT_ID_REQUIREMENT} must have exactly one value"
                )));
            };
            let value = SubjectIdRequirement::from_value(value.as_str())?;
            if requirement.is_some_and(|required| required != value) {
                return Err(SamlError::Invalid(format!(
                    "{SUBJECT_ID_REQUIREMENT} requires different subject identifiers"
                )));
            }
            requirement = Some(value);
        }
        Ok(requirement)
    }

    fn named(&self, name: &'static str) -> impl Iterator<Item = &Attribute> {
        self.0
            .iter()
            .filter(move |attribute| attribute.matches_uri_name(name))
    }

    fn values(&self, name: &'static str) -> Vec<&str> {
        self.named(name)
            .flat_map(Attribute::values)
            .map(AttributeValue::as_str)
            .collect()
    }
}

impl IntoIterator for EntityAttributes {
    type Item = Attribute;
    type IntoIter = std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a EntityAttributes {
    type Item = &'a Attribute;
    type IntoIter = std::slice::Iter<'a, Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Subject identifier that a relying party requires: the value of its
/// `urn:oasis:names:tc:SAML:profiles:subject-id:req` entity attribute.
///
/// Convert one into the [`Attribute`] that publishes it with [`From`].
///
/// # Examples
///
/// ```
/// use saml_rs::{Attribute, AttributeNameFormat, SubjectIdRequirement};
///
/// let attribute = Attribute::from(SubjectIdRequirement::PairwiseId);
/// assert_eq!(attribute.name(), "urn:oasis:names:tc:SAML:profiles:subject-id:req");
/// assert_eq!(attribute.name_format(), Some(&AttributeNameFormat::Uri));
/// assert_eq!(attribute.values()[0].as_str(), "pairwise-id");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectIdRequirement {
    /// `subject-id`: the `subject-id` attribute.
    SubjectId,
    /// `pairwise-id`: the `pairwise-id` attribute.
    PairwiseId,
    /// `none`: no subject identifier.
    None,
    /// `any`: at least one of `subject-id` and `pairwise-id`.
    Any,
}

impl SubjectIdRequirement {
    /// The attribute value: `subject-id`, `pairwise-id`, `none`, or `any`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubjectId => "subject-id",
            Self::PairwiseId => "pairwise-id",
            Self::None => "none",
            Self::Any => "any",
        }
    }

    fn from_value(value: &str) -> Result<Self, SamlError> {
        [Self::SubjectId, Self::PairwiseId, Self::None, Self::Any]
            .into_iter()
            .find(|requirement| requirement.as_str() == value)
            .ok_or_else(|| {
                SamlError::Invalid(format!(
                    "{SUBJECT_ID_REQUIREMENT} has unknown value `{value}`"
                ))
            })
    }
}

impl From<SubjectIdRequirement> for Attribute {
    fn from(requirement: SubjectIdRequirement) -> Self {
        Attribute::new(
            SUBJECT_ID_REQUIREMENT,
            [AttributeValue::new(requirement.as_str())],
        )
        .with_name_format(AttributeNameFormat::Uri)
    }
}

pub(super) fn read_bound_attributes(
    xml: &str,
    roots: &[Node],
    entity: Option<&Node>,
    limits: XmlLimits,
) -> Result<Vec<SamlElement>, SamlError> {
    let (Some(entity), [root]) = (entity, roots) else {
        return Ok(Vec::new());
    };
    if !has_extensions_on_path(root, entity) {
        return Ok(Vec::new());
    }
    let document = parse_saml_with_limits(xml, limits)?;
    let path = super::role::namespaced_path(&document, entity)?;
    Ok(bound_attributes(&path))
}

pub(super) fn bound_attributes(path: &[&SamlElement]) -> Vec<SamlElement> {
    path.iter()
        .filter(|element| {
            element.is(namespace::METADATA, "EntitiesDescriptor")
                || element.is(namespace::METADATA, "EntityDescriptor")
        })
        .flat_map(|element| &element.children)
        .filter(|child| child.is(namespace::METADATA, "Extensions"))
        .flat_map(|extensions| &extensions.children)
        .filter(|extension| extension.is(NAMESPACE, "EntityAttributes"))
        .flat_map(|entity_attributes| &entity_attributes.children)
        .filter(|attribute| attribute.is(namespace::ASSERTION, "Attribute"))
        .cloned()
        .collect()
}

fn has_extensions_on_path(root: &Node, entity: &Node) -> bool {
    let mut node = root;
    loop {
        if node.child_named("Extensions").is_some() {
            return true;
        }
        match node
            .children
            .iter()
            .find(|child| child.start <= entity.start && entity.end <= child.end)
        {
            Some(child) => node = child,
            None => return false,
        }
    }
}

pub(super) fn entity_attributes(elements: &[SamlElement]) -> Result<EntityAttributes, SamlError> {
    elements
        .iter()
        .map(|element| {
            let name = element
                .attr("Name")
                .ok_or_else(|| SamlError::Invalid("entity attribute is missing Name".into()))?;
            let name_format = element.attr("NameFormat").map(collapse_whitespace);
            let values = element
                .children
                .iter()
                .filter(|child| child.is(namespace::ASSERTION, "AttributeValue"))
                .map(|value| AttributeValue::new(value.text.as_str()))
                .collect();
            Ok(Attribute::received(
                name,
                name_format.as_deref(),
                element.attr("FriendlyName"),
                values,
            ))
        })
        .collect::<Result<Vec<_>, SamlError>>()
        .map(EntityAttributes)
}

pub(super) fn validate_entity_attributes(attributes: &[Attribute]) -> Result<(), SamlError> {
    for attribute in attributes {
        attribute.check_writable()?;
        let text = attribute
            .values()
            .iter()
            .map(AttributeValue::as_str)
            .chain([attribute.name()])
            .chain(attribute.friendly_name());
        if !text.flat_map(str::chars).all(is_xml_char) {
            return Err(SamlError::Invalid(format!(
                "entity attribute `{}` contains a character XML cannot represent",
                attribute.name()
            )));
        }
    }
    Ok(())
}

pub(super) fn write_entity_attributes(writer: &mut MetadataWriter, attributes: &[Attribute]) {
    if attributes.is_empty() {
        return;
    }
    writer.start("Extensions", &[]);
    writer.start(
        "mdattr:EntityAttributes",
        &[
            ("xmlns:mdattr", NAMESPACE),
            ("xmlns:saml", namespace::ASSERTION),
        ],
    );
    for attribute in attributes {
        let mut attrs = vec![("Name", attribute.name())];
        if let Some(name_format) = attribute.name_format() {
            attrs.push(("NameFormat", name_format.as_uri()));
        }
        if let Some(friendly_name) = attribute.friendly_name() {
            attrs.push(("FriendlyName", friendly_name));
        }
        if attribute.values().is_empty() {
            writer.empty("saml:Attribute", &attrs);
            continue;
        }
        writer.start("saml:Attribute", &attrs);
        for value in attribute.values() {
            writer.text_element("saml:AttributeValue", value.as_str());
        }
        writer.end("saml:Attribute");
    }
    writer.end("mdattr:EntityAttributes");
    writer.end("Extensions");
}
