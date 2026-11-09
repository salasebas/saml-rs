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

/// SAML attribute with one or more values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    name_format: Option<AttributeNameFormat>,
    values: Vec<AttributeValue>,
}

impl Attribute {
    /// Create a SAML attribute.
    ///
    /// `name_format` is the `NameFormat` URI. `None` omits it.
    pub fn new(
        name: impl Into<String>,
        name_format: Option<String>,
        values: Vec<AttributeValue>,
    ) -> Self {
        Self {
            name: name.into(),
            name_format: name_format.as_deref().map(AttributeNameFormat::from_uri),
            values,
        }
    }

    /// Create a SAML attribute whose name is classified by `name_format`.
    ///
    /// [`AttributeNameFormat::Custom`] with the URI of another variant is
    /// stored as that variant. [`crate::RespondSso::attributes`] rejects an
    /// [`AttributeNameFormat::Basic`] attribute whose name is not an XML name.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{Attribute, AttributeNameFormat, AttributeValue};
    ///
    /// let mail = Attribute::with_name_format(
    ///     "mail",
    ///     AttributeNameFormat::Basic,
    ///     vec![AttributeValue::new("alice@example.com")],
    /// );
    ///
    /// assert_eq!(mail.format(), Some(&AttributeNameFormat::Basic));
    /// assert_eq!(
    ///     mail.name_format(),
    ///     Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
    /// );
    /// ```
    pub fn with_name_format(
        name: impl Into<String>,
        name_format: AttributeNameFormat,
        values: Vec<AttributeValue>,
    ) -> Self {
        let name_format = match name_format {
            AttributeNameFormat::Custom(uri) => AttributeNameFormat::from_uri(&uri),
            AttributeNameFormat::Unspecified
            | AttributeNameFormat::Uri
            | AttributeNameFormat::Basic => name_format,
        };
        Self {
            name: name.into(),
            name_format: Some(name_format),
            values,
        }
    }

    /// Attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `NameFormat` URI, when the attribute carries one.
    pub fn name_format(&self) -> Option<&str> {
        self.name_format.as_ref().map(AttributeNameFormat::as_uri)
    }

    /// `NameFormat`, when the attribute carries one.
    ///
    /// `None` means the `<Attribute>` has no `NameFormat`. SAML treats that
    /// name as [`AttributeNameFormat::Unspecified`].
    pub fn format(&self) -> Option<&AttributeNameFormat> {
        self.name_format.as_ref()
    }

    /// Attribute values.
    pub fn values(&self) -> &[AttributeValue] {
        &self.values
    }
}

/// Collection of SAML attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// Create an attribute collection.
    pub fn new(values: Vec<Attribute>) -> Self {
        Self(values)
    }

    /// Borrow the attributes as a slice.
    pub fn as_slice(&self) -> &[Attribute] {
        &self.0
    }

    /// Find an attribute by name.
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.0.iter().find(|attribute| attribute.name() == name)
    }
}

impl IntoIterator for Attributes {
    type Item = Attribute;
    type IntoIter = std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
