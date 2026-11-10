use crate::constants::authn_context_class_ref;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};

/// Whether an [`AuthnContextReference`] names a class or a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthnContextReferenceKind {
    /// `<AuthnContextClassRef>`.
    Class,
    /// `<AuthnContextDeclRef>`.
    Declaration,
}

/// An authentication context class or declaration reference.
///
/// [`crate::RespondSso::authn_context`] writes it in the assertion's
/// `AuthnContext`. [`RequestedAuthnContext::references`] lists the ones a
/// service provider asked for. [`Self::class`] and [`Self::declaration`]
/// require an absolute URI; a received reference is kept as sent and may not
/// be one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthnContextReference {
    kind: AuthnContextReferenceKind,
    uri: String,
}

impl AuthnContextReference {
    /// An `<AuthnContextClassRef>`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `uri` is not an absolute URI
    /// reference.
    pub fn class(uri: impl Into<String>) -> Result<Self, SamlError> {
        Self::try_new(AuthnContextReferenceKind::Class, uri.into())
    }

    /// An `<AuthnContextDeclRef>`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `uri` is not an absolute URI
    /// reference.
    pub fn declaration(uri: impl Into<String>) -> Result<Self, SamlError> {
        Self::try_new(AuthnContextReferenceKind::Declaration, uri.into())
    }

    /// The class `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`.
    ///
    /// It means the authentication mechanism was not recorded.
    pub fn unspecified_class() -> Self {
        Self::received(
            AuthnContextReferenceKind::Class,
            authn_context_class_ref::UNSPECIFIED,
        )
    }

    fn try_new(kind: AuthnContextReferenceKind, uri: String) -> Result<Self, SamlError> {
        if !is_absolute_uri_reference(&uri) {
            return Err(SamlError::Invalid(
                "an authentication context reference must be an absolute URI reference".into(),
            ));
        }
        Ok(Self::received(kind, &uri))
    }

    fn received(kind: AuthnContextReferenceKind, uri: &str) -> Self {
        Self {
            kind,
            uri: collapse_whitespace(uri),
        }
    }

    /// Class or declaration.
    pub fn kind(&self) -> AuthnContextReferenceKind {
        self.kind
    }

    /// The reference URI, with XML Schema `anyURI` whitespace collapsed.
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// `Comparison` on a `<RequestedAuthnContext>`.
///
/// An omitted attribute is [`Self::Exact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthnContextComparison {
    /// `exact`.
    Exact,
    /// `minimum`.
    Minimum,
    /// `maximum`.
    Maximum,
    /// `better`.
    Better,
}

impl AuthnContextComparison {
    fn from_attribute(value: &str) -> Result<Self, SamlError> {
        match value {
            "exact" => Ok(Self::Exact),
            "minimum" => Ok(Self::Minimum),
            "maximum" => Ok(Self::Maximum),
            "better" => Ok(Self::Better),
            _ => Err(SamlError::Invalid(
                "RequestedAuthnContext Comparison must be exact, minimum, maximum, or better"
                    .into(),
            )),
        }
    }
}

/// `<RequestedAuthnContext>` of a received `<AuthnRequest>`.
///
/// The references are in request order, most preferred first, and are all
/// classes or all declarations. When none can be met, answer with
/// [`crate::Status::responder`] and, optionally,
/// [`crate::SubordinateStatusCode::no_authn_context`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAuthnContext {
    comparison: AuthnContextComparison,
    references: Vec<AuthnContextReference>,
}

impl RequestedAuthnContext {
    /// How the authentication context of the response is compared with
    /// [`Self::references`].
    pub fn comparison(&self) -> AuthnContextComparison {
        self.comparison
    }

    /// Requested references, most preferred first.
    pub fn references(&self) -> &[AuthnContextReference] {
        &self.references
    }

    /// Reject `achieved` when the comparison is exact and it is not one of
    /// the requested references. The other comparisons are judged by the
    /// caller.
    pub(crate) fn ensure_met_by(&self, achieved: &AuthnContextReference) -> Result<(), SamlError> {
        match self.comparison {
            AuthnContextComparison::Exact if !self.references.contains(achieved) => {
                Err(SamlError::Invalid(format!(
                    "the authentication context {} is not one of the exactly requested contexts",
                    achieved.uri()
                )))
            }
            AuthnContextComparison::Exact
            | AuthnContextComparison::Minimum
            | AuthnContextComparison::Maximum
            | AuthnContextComparison::Better => Ok(()),
        }
    }
}

pub(super) fn requested_authn_context_from_extract(
    extract: &Value,
) -> Result<Option<RequestedAuthnContext>, SamlError> {
    match extract.get("requestedAuthnContext") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Str(_)) => {}
        Some(Value::Array(_) | Value::Object(_)) => {
            return Err(SamlError::Invalid(
                "AuthnRequest RequestedAuthnContext must occur once".into(),
            ))
        }
    }
    let comparison = extract
        .get_str("requestedAuthnContextComparison")
        .map(AuthnContextComparison::from_attribute)
        .transpose()?
        .unwrap_or(AuthnContextComparison::Exact);
    let classes = reference_texts(extract, "authnContextClassRef");
    let declarations = reference_texts(extract, "authnContextDeclRef");
    let references =
        match (classes.is_empty(), declarations.is_empty()) {
            (false, true) => parsed_references(AuthnContextReferenceKind::Class, &classes),
            (true, false) => {
                parsed_references(AuthnContextReferenceKind::Declaration, &declarations)
            }
            (true, true) => return Err(SamlError::Invalid(
                "RequestedAuthnContext must contain AuthnContextClassRef or AuthnContextDeclRef"
                    .into(),
            )),
            (false, false) => return Err(SamlError::Invalid(
                "RequestedAuthnContext must not mix AuthnContextClassRef and AuthnContextDeclRef"
                    .into(),
            )),
        };
    Ok(Some(RequestedAuthnContext {
        comparison,
        references,
    }))
}

fn reference_texts<'a>(extract: &'a Value, path: &str) -> Vec<&'a str> {
    match extract.get(path) {
        Some(Value::Str(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        Some(Value::Null | Value::Object(_)) | None => Vec::new(),
    }
}

fn parsed_references(kind: AuthnContextReferenceKind, uris: &[&str]) -> Vec<AuthnContextReference> {
    uris.iter()
        .map(|uri| AuthnContextReference::received(kind, uri))
        .collect()
}
