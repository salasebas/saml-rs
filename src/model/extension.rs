use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::dom::{parse_standalone_element, XmlLimits};

/// The target namespaces of the SAML V2.0 OASIS Standard schemas, and the
/// SAML V1.x assertion and protocol namespaces.
const SAML_DEFINED_NAMESPACES: &[&str] = &[
    namespace::PROTOCOL,
    namespace::ASSERTION,
    namespace::METADATA,
    "urn:oasis:names:tc:SAML:2.0:ac",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalizedTelephony",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig",
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE",
    "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500",
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML",
    "urn:oasis:names:tc:SAML:1.0:assertion",
    "urn:oasis:names:tc:SAML:1.0:protocol",
];

/// A standalone XML element for an outbound AuthnRequest's `<Extensions>`.
///
/// Add it to a request with [`StartSso::extension`](crate::StartSso::extension).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionElement(String);

impl ExtensionElement {
    /// Parse an extension element and keep its XML without the surrounding
    /// declaration, comments, processing instructions, or whitespace.
    ///
    /// The root element must use a namespace that SAML does not define. The
    /// namespaces of approved SAML extensions, such as the asynchronous logout
    /// extension's `urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo`, are
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Xml`] if the input is not one well-formed XML
    /// element with its name prefixes declared or if it contains a DOCTYPE.
    /// Returns [`SamlError::LimitExceeded`] if the input exceeds the default
    /// [`XmlLimits`]. Returns [`SamlError::Invalid`] if the root element is in
    /// no namespace or in a namespace that a SAML V2.0 schema, such as the
    /// protocol, assertion, metadata, or authentication context schema,
    /// declares as its target, or in the SAML V1.x assertion or protocol
    /// namespace.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        let (root, namespace) = parse_standalone_element(xml, XmlLimits::default())?;
        if namespace.is_empty() || SAML_DEFINED_NAMESPACES.contains(&namespace.as_str()) {
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
