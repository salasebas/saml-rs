use crate::config::NameIdFormat;
use crate::constants::name_id_format;
use crate::entity::generate_id;
use crate::error::SamlError;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};

use super::extract::name_id_format_from_uri;

const MAX_OPAQUE_NAME_ID_CHARS: usize = 256;

/// Reject a NameID format that is written but is not an absolute URI
/// reference. `None` is an omitted format and passes.
pub(crate) fn validate_name_id_format(format_uri: Option<&str>) -> Result<(), SamlError> {
    match format_uri {
        Some(format) if !is_absolute_uri_reference(format) => Err(SamlError::Invalid(
            "a NameID format must be an absolute URI reference with at least one non-whitespace character"
                .into(),
        )),
        Some(_) | None => Ok(()),
    }
}

pub(crate) fn is_name_id_format(format_uri: Option<&str>, expected: &str) -> bool {
    format_uri.is_some_and(|format| collapse_whitespace(format) == expected)
}

/// Reject a persistent or transient `NameID` value longer than 256
/// characters. Other formats have no length limit.
pub(crate) fn validate_issued_name_id_length(
    format_uri: Option<&str>,
    value: &str,
) -> Result<(), SamlError> {
    let format = if is_name_id_format(format_uri, name_id_format::PERSISTENT) {
        "persistent"
    } else if is_name_id_format(format_uri, name_id_format::TRANSIENT) {
        "transient"
    } else {
        return Ok(());
    };
    if value.chars().count() > MAX_OPAQUE_NAME_ID_CHARS {
        return Err(SamlError::Invalid(format!(
            "a {format} NameID must not exceed {MAX_OPAQUE_NAME_ID_CHARS} characters"
        )));
    }
    Ok(())
}

/// NameID value, format, and optional qualifier attributes.
///
/// [`Self::new`] leaves the qualifiers unset. Response generation writes the
/// value, format, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`.
///
/// [`Self::generate_transient`], [`Self::generate_persistent`], and
/// [`Self::persistent`] create the identifiers an identity provider issues in
/// those two formats. [`Self::new`] takes any value in any format. An identity
/// provider response rejects a persistent or transient value longer than 256
/// characters, whichever constructor created it. A message that writes the
/// `NameId` rejects a format that is not an absolute URI reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
    sp_provided_id: Option<String>,
}

impl NameId {
    /// Create a NameID value.
    pub fn new(value: impl Into<String>, format: Option<NameIdFormat>) -> Self {
        Self::with_qualifiers(value, format, None, None, None)
    }

    /// Create a new transient identifier.
    ///
    /// The value is 160 random bits, written as an XML ID of 41 characters.
    /// Each call returns a different value.
    pub fn generate_transient() -> Self {
        Self::new(generate_id(), Some(NameIdFormat::Transient))
    }

    /// Create a new persistent identifier for one principal at one service
    /// provider.
    ///
    /// The value is 160 random bits, written as 41 characters, and is not
    /// derived from the principal. Each call returns a different value: store
    /// it for that principal and service provider, and pass the stored value
    /// to [`Self::persistent`] on later responses. Do not issue it for another
    /// principal.
    pub fn generate_persistent() -> Self {
        Self::new(generate_id(), Some(NameIdFormat::Persistent))
    }

    /// Wrap a persistent identifier this identity provider already
    /// established.
    ///
    /// The caller keeps the value opaque, unique for the service provider, and
    /// bound to one principal. [`Self::generate_persistent`] creates such a
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the value is longer than 256
    /// characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{NameId, NameIdFormat};
    ///
    /// let first = NameId::generate_persistent();
    /// let stored = first.value().to_string();
    ///
    /// let later = NameId::persistent(stored)?;
    /// assert_eq!(later, first);
    /// assert_eq!(later.format(), Some(&NameIdFormat::Persistent));
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn persistent(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_issued_name_id_length(Some(name_id_format::PERSISTENT), &value)?;
        Ok(Self::new(value, Some(NameIdFormat::Persistent)))
    }

    /// Create a NameID with qualifier attributes.
    ///
    /// `None` omits the attribute. `Some("")` is an empty value.
    pub fn with_qualifiers(
        value: impl Into<String>,
        format: Option<NameIdFormat>,
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
        sp_provided_id: Option<String>,
    ) -> Self {
        Self {
            value: value.into(),
            format,
            name_qualifier,
            sp_name_qualifier,
            sp_provided_id,
        }
    }

    /// Borrow the NameID text.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// NameID format, when extracted.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// `NameQualifier`, when present.
    pub fn name_qualifier(&self) -> Option<&str> {
        self.name_qualifier.as_deref()
    }

    /// `SPNameQualifier`, when present.
    pub fn sp_name_qualifier(&self) -> Option<&str> {
        self.sp_name_qualifier.as_deref()
    }

    /// `SPProvidedID`, when present.
    pub fn sp_provided_id(&self) -> Option<&str> {
        self.sp_provided_id.as_deref()
    }
}

/// AuthnRequest NameIDPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    format: Option<NameIdFormat>,
    sp_name_qualifier: Option<String>,
    creation_request: NameIdCreationRequest,
}

/// AuthnRequest NameID creation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameIdCreationRequest {
    /// The request did not specify whether the IdP may create a new identifier.
    Unspecified,
    /// The IdP may create a new identifier.
    AllowCreate,
    /// The IdP must not create a new identifier.
    DoNotAllowCreate,
}

impl NameIdPolicy {
    /// Create a NameIDPolicy model.
    pub fn new(format: Option<NameIdFormat>, creation_request: NameIdCreationRequest) -> Self {
        Self {
            format,
            sp_name_qualifier: None,
            creation_request,
        }
    }

    /// Create a NameIDPolicy without an AllowCreate preference.
    pub fn unspecified(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::Unspecified)
    }

    /// Create a NameIDPolicy allowing the IdP to create a new identifier.
    pub fn allow_creation(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::AllowCreate)
    }

    /// Create a NameIDPolicy forbidding the IdP from creating a new identifier.
    pub fn disallow_creation(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::DoNotAllowCreate)
    }

    /// Set the requested `SPNameQualifier`.
    pub fn with_sp_name_qualifier(mut self, sp_name_qualifier: impl Into<String>) -> Self {
        self.sp_name_qualifier = Some(sp_name_qualifier.into());
        self
    }

    pub(crate) fn from_parsed(
        format: Option<NameIdFormat>,
        sp_name_qualifier: Option<String>,
        allow_create: Option<bool>,
    ) -> Option<Self> {
        if format.is_none() && sp_name_qualifier.is_none() && allow_create.is_none() {
            return None;
        }
        let creation_request = match allow_create {
            Some(true) => NameIdCreationRequest::AllowCreate,
            Some(false) => NameIdCreationRequest::DoNotAllowCreate,
            None => NameIdCreationRequest::Unspecified,
        };
        Some(Self {
            format,
            sp_name_qualifier,
            creation_request,
        })
    }

    /// Requested NameID format.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// Requested `SPNameQualifier`, when present.
    ///
    /// It names the service provider or affiliation whose namespace the
    /// returned identifier belongs to.
    pub fn sp_name_qualifier(&self) -> Option<&str> {
        self.sp_name_qualifier.as_deref()
    }

    /// NameID creation request.
    pub fn creation_request(&self) -> NameIdCreationRequest {
        self.creation_request
    }

    /// Reject an issued `SPNameQualifier` that differs from the requested one
    /// when the policy asks for a SAML-defined format other than
    /// `unspecified`.
    pub(crate) fn ensure_sp_name_qualifier_met_by(
        &self,
        issued: Option<&str>,
    ) -> Result<(), SamlError> {
        match self.sp_name_qualifier.as_deref() {
            Some(requested) if self.requests_saml_defined_format() && issued != Some(requested) => {
                Err(SamlError::Invalid(format!(
                    "the NameIDPolicy requests SPNameQualifier {requested}, which the issued NameID must carry"
                )))
            }
            Some(_) | None => Ok(()),
        }
    }

    fn requests_saml_defined_format(&self) -> bool {
        let Some(format) = &self.format else {
            return false;
        };
        match name_id_format_from_uri(&collapse_whitespace(format.as_uri())) {
            NameIdFormat::EmailAddress
            | NameIdFormat::Persistent
            | NameIdFormat::Transient
            | NameIdFormat::Entity
            | NameIdFormat::Kerberos
            | NameIdFormat::WindowsDomainQualifiedName
            | NameIdFormat::X509SubjectName => true,
            NameIdFormat::Unspecified | NameIdFormat::Custom(_) => false,
        }
    }

    /// Whether the IdP may create a new identifier.
    pub fn allow_create(&self) -> Option<bool> {
        match self.creation_request {
            NameIdCreationRequest::Unspecified => None,
            NameIdCreationRequest::AllowCreate => Some(true),
            NameIdCreationRequest::DoNotAllowCreate => Some(false),
        }
    }
}

/// SubjectConfirmation captured from the validated flow result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectConfirmation {
    raw_xml: String,
}

impl SubjectConfirmation {
    /// Create a subject confirmation from extractor context XML.
    pub fn from_raw_xml(raw_xml: impl Into<String>) -> Self {
        Self {
            raw_xml: raw_xml.into(),
        }
    }

    /// Borrow the raw confirmation XML captured by the extractor.
    pub fn raw_xml(&self) -> &str {
        &self.raw_xml
    }
}

/// SAML subject.
///
/// An accepted assertion's subject lists its `<SubjectConfirmation>` elements
/// in [`Self::confirmations`]. The identity provider methods that issue an
/// assertion, such as `respond_sso`, take only the `NameId` and write their own
/// bearer confirmation. They return [`SamlError::Unsupported`] for a subject
/// with confirmations, including the subject of an accepted assertion; build a
/// new subject from its `NameId` to re-issue it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    name_id: NameId,
    confirmations: Vec<SubjectConfirmation>,
}

impl Subject {
    /// Create a subject.
    pub fn new(name_id: NameId, confirmations: Vec<SubjectConfirmation>) -> Self {
        Self {
            name_id,
            confirmations,
        }
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// Subject confirmations.
    pub fn confirmations(&self) -> &[SubjectConfirmation] {
        &self.confirmations
    }
}

/// Subject requested by an `<AuthnRequest>` (Core §3.4.1).
///
/// The identity provider decides whether an assertion subject strongly matches
/// (Core §3.4.1.4, §3.3.4, Errata 05 E75). This library does not compare them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedSubject {
    identifier: RequestedSubjectIdentifier,
    confirmations: Vec<SubjectConfirmation>,
}

/// Identifier inside a requested [`RequestedSubject`] (Core §3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedSubjectIdentifier {
    /// No `<BaseID>`, `<NameID>`, or `<EncryptedID>`. The presenter is the subject.
    NoIdentifier,
    /// `<NameID>` content and attributes.
    NameId(NameId),
    /// `<BaseID>`, not decoded.
    BaseId,
    /// `<EncryptedID>` this identity provider did not decrypt: it has no
    /// decryption key, the request is unsigned and its data encryption is not
    /// AES-GCM, or the ciphertext does not decrypt to one `<NameID>`, for
    /// example under an RSA-v1.5 key transport that is not selected. A
    /// decrypted one is [`Self::NameId`]. A decryption key that does not
    /// load is an error of `receive_sso` instead.
    EncryptedId,
}

impl RequestedSubject {
    pub(crate) fn new(
        identifier: RequestedSubjectIdentifier,
        confirmations: Vec<SubjectConfirmation>,
    ) -> Self {
        Self {
            identifier,
            confirmations,
        }
    }

    /// Requested identifier.
    pub fn identifier(&self) -> &RequestedSubjectIdentifier {
        &self.identifier
    }

    /// `<NameID>` when the identifier is [`RequestedSubjectIdentifier::NameId`].
    pub fn name_id(&self) -> Option<&NameId> {
        match &self.identifier {
            RequestedSubjectIdentifier::NameId(name_id) => Some(name_id),
            RequestedSubjectIdentifier::NoIdentifier
            | RequestedSubjectIdentifier::BaseId
            | RequestedSubjectIdentifier::EncryptedId => None,
        }
    }

    /// `<SubjectConfirmation>` elements, in document order.
    ///
    /// An empty slice means the presenter is the only attesting entity
    /// (Core §3.4.1).
    pub fn confirmations(&self) -> &[SubjectConfirmation] {
        &self.confirmations
    }
}
