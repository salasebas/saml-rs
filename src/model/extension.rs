use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{parse_standalone_element, XmlLimits};

/// A standalone XML element for an outbound AuthnRequest's `<Extensions>`.
///
/// Add it to a request with [`StartSso::extension`](crate::StartSso::extension).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionElement(String);

impl ExtensionElement {
    /// Parse an extension element and keep its XML without the surrounding
    /// declaration, comments, processing instructions, or whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Xml`] if the input is not one well-formed XML
    /// element with its name prefixes declared or if it contains a DOCTYPE.
    /// Returns [`SamlError::LimitExceeded`] if the input exceeds the default
    /// [`XmlLimits`]. Returns [`SamlError::Invalid`] if the root element is in
    /// no namespace or in the SAML protocol, assertion, or metadata namespace.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        let (root, namespace) = parse_standalone_element(xml, XmlLimits::default())?;
        if matches!(
            namespace.as_str(),
            "" | namespace::PROTOCOL | namespace::ASSERTION | namespace::METADATA
        ) {
            return Err(SamlError::Invalid(format!(
                "extension element {} must use a non-SAML namespace",
                root.local_name
            )));
        }
        let element = xml
            .get(root.start..root.end)
            .ok_or_else(|| SamlError::xml("extension element is outside the document"))?;
        Ok(Self(element.to_owned()))
    }

    pub(crate) fn xml(&self) -> &str {
        &self.0
    }
}
