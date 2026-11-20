use crate::constants::attribute_name_format;

/// A single SAML attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValue(String);

impl AttributeValue {
    /// Wrap an attribute value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the attribute value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Classification of a SAML attribute name: the `NameFormat` of an
/// `<Attribute>`.
///
/// SAML treats the name of an `<Attribute>` without `NameFormat` as
/// [`Self::Unspecified`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributeNameFormat {
    /// Unspecified format. The name's interpretation is left to the deployment.
    Unspecified,
    /// URI reference format. The name is a URI reference.
    Uri,
    /// Basic format. The name is an XML name.
    Basic,
    /// Deployment-specific attribute name format URI.
    Custom(String),
}

impl AttributeNameFormat {
    /// Return the SAML attribute name format URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Unspecified => attribute_name_format::UNSPECIFIED,
            Self::Uri => attribute_name_format::URI,
            Self::Basic => attribute_name_format::BASIC,
            Self::Custom(uri) => uri.as_str(),
        }
    }

    pub(crate) fn from_uri(uri: &str) -> Self {
        match uri {
            attribute_name_format::UNSPECIFIED => Self::Unspecified,
            attribute_name_format::URI => Self::Uri,
            attribute_name_format::BASIC => Self::Basic,
            _ => Self::Custom(uri.to_string()),
        }
    }
}

/// A SAML `<Attribute>`: a name, an optional `NameFormat`, and its values.
///
/// # Examples
///
/// ```
/// use saml_rs::{Attribute, AttributeNameFormat, AttributeValue};
///
/// let groups = Attribute::new(
///     "groups",
///     [AttributeValue::new("staff"), AttributeValue::new("admins")],
/// )
/// .with_name_format(AttributeNameFormat::Basic);
///
/// assert_eq!(groups.name_format(), Some(&AttributeNameFormat::Basic));
/// assert_eq!(groups.values().len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    name_format: Option<AttributeNameFormat>,
    values: Vec<AttributeValue>,
}

impl Attribute {
    /// Create an attribute without `NameFormat`, in which case SAML treats
    /// its name as [`AttributeNameFormat::Unspecified`].
    ///
    /// The values are kept in order. An attribute without values writes no
    /// `AttributeValue`.
    pub fn new(name: impl Into<String>, values: impl IntoIterator<Item = AttributeValue>) -> Self {
        Self {
            name: name.into(),
            name_format: None,
            values: values.into_iter().collect(),
        }
    }

    /// Replace the `NameFormat`.
    ///
    /// [`AttributeNameFormat::Custom`] with the URI of another variant is
    /// stored as that variant. [`crate::SsoAssertion::with_attributes`] rejects an
    /// [`AttributeNameFormat::Basic`] attribute whose name is not an XML name,
    /// and a `NameFormat` that is not an absolute URI reference.
    pub fn with_name_format(mut self, name_format: AttributeNameFormat) -> Self {
        self.name_format = Some(match name_format {
            AttributeNameFormat::Custom(uri) => AttributeNameFormat::from_uri(&uri),
            AttributeNameFormat::Unspecified
            | AttributeNameFormat::Uri
            | AttributeNameFormat::Basic => name_format,
        });
        self
    }

    pub(super) fn received(
        name: &str,
        name_format: Option<&str>,
        values: Vec<AttributeValue>,
    ) -> Self {
        Self {
            name: name.to_string(),
            name_format: name_format.map(AttributeNameFormat::from_uri),
            values,
        }
    }

    /// Attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `NameFormat`, when the attribute carries one.
    ///
    /// `None` means the `<Attribute>` has no `NameFormat`. SAML treats that
    /// name as [`AttributeNameFormat::Unspecified`].
    /// [`AttributeNameFormat::as_uri`] gives the URI.
    pub fn name_format(&self) -> Option<&AttributeNameFormat> {
        self.name_format.as_ref()
    }

    /// Attribute values, in order.
    pub fn values(&self) -> &[AttributeValue] {
        &self.values
    }
}

/// The attributes of an assertion, in order.
///
/// # Examples
///
/// ```
/// use saml_rs::{Attribute, AttributeValue, Attributes};
///
/// let attributes = Attributes::new([
///     Attribute::new("mail", [AttributeValue::new("alice@example.com")]),
///     Attribute::new("groups", [AttributeValue::new("staff"), AttributeValue::new("admins")]),
/// ]);
///
/// assert_eq!(attributes.first_value("mail"), Some("alice@example.com"));
/// assert_eq!(attributes.first_value("groups"), Some("staff"));
///
/// let mut names = Vec::new();
/// for attribute in &attributes {
///     names.push(attribute.name());
/// }
/// assert_eq!(names, ["mail", "groups"]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// Create an attribute collection in the given order.
    pub fn new(attributes: impl IntoIterator<Item = Attribute>) -> Self {
        attributes.into_iter().collect()
    }

    /// Borrow the attributes as a slice.
    pub fn as_slice(&self) -> &[Attribute] {
        &self.0
    }

    /// Iterate over the attributes in order.
    pub fn iter(&self) -> std::slice::Iter<'_, Attribute> {
        self.0.iter()
    }

    /// Find the first attribute with `name`.
    ///
    /// A received response has one attribute for each `Name` and `NameFormat`
    /// pair, so the same name can appear more than once.
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.0.iter().find(|attribute| attribute.name() == name)
    }

    /// The first value of the attribute [`Self::get`] finds for `name`.
    ///
    /// `None` when no attribute has `name` or that attribute has no value.
    /// The other values are ignored; read [`Attribute::values`] for an
    /// attribute that can have several.
    pub fn first_value(&self, name: &str) -> Option<&str> {
        self.get(name)?.values().first().map(AttributeValue::as_str)
    }
}

impl FromIterator<Attribute> for Attributes {
    fn from_iter<I: IntoIterator<Item = Attribute>>(attributes: I) -> Self {
        Self(attributes.into_iter().collect())
    }
}

impl IntoIterator for Attributes {
    type Item = Attribute;
    type IntoIter = std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Attributes {
    type Item = &'a Attribute;
    type IntoIter = std::slice::Iter<'a, Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
