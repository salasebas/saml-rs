use super::authn_context::{AuthnContextReference, AuthnContextReferenceKind};
use crate::constants::namespace;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::dom::XmlLimits;
use crate::xml::protocol_element::{parse_saml_with_limits, SamlElement};

/// The authentication context reported by one accepted `AuthnStatement`.
///
/// This is information from the identity provider. The service provider does
/// not compare it with the requested context or assign an assurance level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnContext {
    class_reference: Option<AuthnContextReference>,
    declaration_reference: Option<AuthnContextReference>,
    has_declaration: bool,
    authenticating_authorities: Vec<String>,
}

impl AuthnContext {
    /// The `AuthnContextClassRef`, when present.
    pub fn class_reference(&self) -> Option<&AuthnContextReference> {
        self.class_reference.as_ref()
    }

    /// The `AuthnContextDeclRef`, when present.
    pub fn declaration_reference(&self) -> Option<&AuthnContextReference> {
        self.declaration_reference.as_ref()
    }

    /// Whether a by-value `AuthnContextDecl` is present. Its content is not modeled.
    pub fn has_declaration(&self) -> bool {
        self.has_declaration
    }

    /// Upstream authentication authorities in document order, with `anyURI`
    /// whitespace collapsed. Repeated values are retained.
    pub fn authenticating_authorities(&self) -> &[String] {
        &self.authenticating_authorities
    }

    pub(super) fn from_element(element: &SamlElement) -> Self {
        let reference = |name, kind| {
            element
                .children
                .iter()
                .find(|child| child.is(namespace::ASSERTION, name))
                .map(|child| AuthnContextReference::received(kind, &child.text))
        };
        Self {
            class_reference: reference("AuthnContextClassRef", AuthnContextReferenceKind::Class),
            declaration_reference: reference(
                "AuthnContextDeclRef",
                AuthnContextReferenceKind::Declaration,
            ),
            has_declaration: element
                .children
                .iter()
                .any(|child| child.is(namespace::ASSERTION, "AuthnContextDecl")),
            authenticating_authorities: element
                .children
                .iter()
                .filter(|child| child.is(namespace::ASSERTION, "AuthenticatingAuthority"))
                .map(|child| collapse_whitespace(&child.text))
                .collect(),
        }
    }
}

/// The optional network location reported by one accepted `AuthnStatement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectLocality {
    address: Option<String>,
    dns_name: Option<String>,
}

impl SubjectLocality {
    /// The reported `Address`, when present.
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// The reported `DNSName`, when present.
    pub fn dns_name(&self) -> Option<&str> {
        self.dns_name.as_deref()
    }

    pub(super) fn from_element(element: &SamlElement) -> Self {
        Self {
            address: element.attr("Address").map(str::to_string),
            dns_name: element.attr("DNSName").map(str::to_string),
        }
    }
}

pub(super) struct StatementChildren {
    pub(super) authn_context: AuthnContext,
    pub(super) subject_locality: Option<SubjectLocality>,
}

impl StatementChildren {
    fn from_element(statement: &SamlElement) -> Result<Self, SamlError> {
        let context = at_most_one_child(statement, "AuthnContext")?.ok_or_else(|| {
            SamlError::ProtocolProfile("AuthnStatement is missing AuthnContext".into())
        })?;
        Ok(Self {
            authn_context: AuthnContext::from_element(context),
            subject_locality: at_most_one_child(statement, "SubjectLocality")?
                .map(SubjectLocality::from_element),
        })
    }
}

fn at_most_one_child<'a>(
    statement: &'a SamlElement,
    name: &str,
) -> Result<Option<&'a SamlElement>, SamlError> {
    let mut children = statement
        .children
        .iter()
        .filter(|child| child.is(namespace::ASSERTION, name));
    let first = children.next();
    if children.next().is_some() {
        return Err(SamlError::ProtocolProfile(format!(
            "AuthnStatement has more than one {name}"
        )));
    }
    Ok(first)
}

pub(super) fn statement_children(
    extract: &Value,
    xml: &str,
) -> Result<Vec<StatementChildren>, SamlError> {
    let document = parse_saml_with_limits(xml, XmlLimits::unbounded())?;
    let assertion_id = extract.get_str(crate::xml::fields::login_response::ASSERTION_ID);
    let assertion = std::iter::once(&document)
        .chain(document.children.iter())
        .find(|element| {
            element.is(namespace::ASSERTION, "Assertion") && element.attr("ID") == assertion_id
        })
        .ok_or_else(|| {
            SamlError::Invalid("extracted AuthnStatement has no matching assertion".into())
        })?;
    assertion
        .children
        .iter()
        .filter(|child| child.is(namespace::ASSERTION, "AuthnStatement"))
        .map(StatementChildren::from_element)
        .collect()
}
