use crate::config::{validate_entity_id_syntax, IdentifierEncryptionPolicy, NameIdFormat};
use crate::constants::name_id_format;
use crate::entity::generate_id;
use crate::error::SamlError;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};
use crate::xml::OutboundNameIdQualifiers;

const MAX_OPAQUE_NAME_ID_CHARS: usize = 256;
const ENCRYPTED_NAME_ID_POLICY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";

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

pub(crate) fn validate_issued_entity_name_id(
    format_uri: Option<&str>,
    value: &str,
    qualifiers: OutboundNameIdQualifiers<'_>,
) -> Result<(), SamlError> {
    if !is_name_id_format(format_uri, name_id_format::ENTITY) {
        return Ok(());
    }
    if validate_entity_id_syntax(value).is_err() {
        return Err(SamlError::Invalid(
            "an entity NameID must be an absolute URI reference of at most 1024 characters with collapsed whitespace"
                .into(),
        ));
    }
    let OutboundNameIdQualifiers {
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    } = qualifiers;
    if name_qualifier.is_some() || sp_name_qualifier.is_some() || sp_provided_id.is_some() {
        return Err(SamlError::Invalid(
            "an entity NameID must omit NameQualifier, SPNameQualifier, and SPProvidedID".into(),
        ));
    }
    Ok(())
}

/// NameID value, format, and optional qualifier attributes.
///
/// [`Self::new`] leaves the `Format` and the qualifiers unset; the `with_`
/// methods set them. Response generation writes the value, `Format`,
/// `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`.
///
/// [`Self::generate_transient`], [`Self::generate_persistent`], and
/// [`Self::persistent`] create the identifiers an identity provider issues in
/// those two formats. [`Self::new`] takes any value, and
/// [`Self::with_format`] any format. An identity provider response rejects a
/// persistent or transient value longer than 256 characters, whichever
/// constructor created it. It also rejects an `entity` value that is not an
/// absolute URI reference of at most 1024 characters with collapsed
/// whitespace, and an `entity` `NameId` with any qualifier. A message that
/// writes the `NameId` rejects a format that is not an absolute URI
/// reference.
///
/// # Examples
///
/// ```
/// use saml_rs::{NameId, NameIdFormat};
///
/// let mail = NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress);
/// assert_eq!(mail.format(), Some(&NameIdFormat::EmailAddress));
/// assert_eq!(mail.sp_name_qualifier(), None);
///
/// let pseudonym =
///     NameId::generate_persistent().with_sp_name_qualifier("https://affiliation.example.com");
/// assert_eq!(pseudonym.format(), Some(&NameIdFormat::Persistent));
/// assert_eq!(
///     pseudonym.sp_name_qualifier(),
///     Some("https://affiliation.example.com")
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
    sp_provided_id: Option<String>,
}

impl NameId {
    /// Create a NameID with no `Format` and no qualifiers.
    ///
    /// An identity provider writes a `NameId` without a format with its first
    /// configured NameID format, in a response and in a `LogoutRequest`, and
    /// omits `Format` when none is configured. A service provider's
    /// `LogoutRequest` omits it. Where `Format` is omitted, `unspecified` is in
    /// effect.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Create a new transient identifier.
    ///
    /// The value is 160 random bits, written as an XML ID of 41 characters.
    /// Each call returns a different value.
    pub fn generate_transient() -> Self {
        Self::new(generate_id()).with_format(NameIdFormat::Transient)
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
        Self::new(generate_id()).with_format(NameIdFormat::Persistent)
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
        Ok(Self::new(value).with_format(NameIdFormat::Persistent))
    }

    /// Replace the `Format`.
    pub fn with_format(mut self, format: NameIdFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Set the `NameQualifier`. An empty value writes an empty attribute.
    pub fn with_name_qualifier(mut self, name_qualifier: impl Into<String>) -> Self {
        self.name_qualifier = Some(name_qualifier.into());
        self
    }

    /// Set the `SPNameQualifier`. An empty value writes an empty attribute.
    pub fn with_sp_name_qualifier(mut self, sp_name_qualifier: impl Into<String>) -> Self {
        self.sp_name_qualifier = Some(sp_name_qualifier.into());
        self
    }

    /// Set the `SPProvidedID`. An empty value writes an empty attribute.
    pub fn with_sp_provided_id(mut self, sp_provided_id: impl Into<String>) -> Self {
        self.sp_provided_id = Some(sp_provided_id.into());
        self
    }

    pub(crate) fn received(
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

    /// `Format`, when set.
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

    pub(super) fn strongly_matches(&self, other: &Self) -> bool {
        self.matches_value_and_qualifiers(other.value(), other.into())
            && self.effective_format() == other.effective_format()
    }

    fn effective_format(&self) -> String {
        name_id_format_in_effect(self.format().map(NameIdFormat::as_uri))
    }

    fn matches_value_and_qualifiers(
        &self,
        value: &str,
        qualifiers: OutboundNameIdQualifiers,
    ) -> bool {
        self.value() == value
            && self.name_qualifier() == qualifiers.name_qualifier
            && self.sp_name_qualifier() == qualifiers.sp_name_qualifier
            && self.sp_provided_id() == qualifiers.sp_provided_id
    }
}

impl<'a> From<&'a NameId> for OutboundNameIdQualifiers<'a> {
    fn from(name_id: &'a NameId) -> Self {
        Self {
            name_qualifier: name_id.name_qualifier(),
            sp_name_qualifier: name_id.sp_name_qualifier(),
            sp_provided_id: name_id.sp_provided_id(),
        }
    }
}

/// The `<NameIDPolicy>` of a received `<AuthnRequest>`.
///
/// [`crate::AuthnRequest::name_id_policy`] returns it. A service provider uses
/// [`crate::SpConfig`] for format and creation, and
/// [`crate::StartSso::sp_name_qualifier`] for the outbound qualifier.
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
    ///
    /// The format is read after XML whitespace collapse, so a Core §8.3 format
    /// URI with surrounding whitespace is its named variant. The special
    /// `urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted` URI is
    /// represented as [`NameIdFormat::Custom`].
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// Requested `SPNameQualifier`, when present.
    ///
    /// It names the service provider or affiliation whose namespace the
    /// returned identifier belongs to.
    /// Use trusted federation data to decide whether the requester may use
    /// that namespace before selecting an identifier.
    pub fn sp_name_qualifier(&self) -> Option<&str> {
        self.sp_name_qualifier.as_deref()
    }

    /// NameID creation request.
    pub fn creation_request(&self) -> NameIdCreationRequest {
        self.creation_request
    }

    pub(crate) fn ensure_met_by(
        &self,
        issued_format: Option<&str>,
        issued_sp_name_qualifier: Option<&str>,
        recipient_entity_id: Option<&str>,
        identifier_encryption: IdentifierEncryptionPolicy,
    ) -> Result<(), SamlError> {
        let requested_uri = name_id_format_in_effect(self.format().map(NameIdFormat::as_uri));
        if requested_uri == ENCRYPTED_NAME_ID_POLICY_FORMAT {
            return match identifier_encryption {
                IdentifierEncryptionPolicy::EncryptIdentifiers => Ok(()),
                IdentifierEncryptionPolicy::PlaintextIdentifiers => {
                    Err(SamlError::NameIdPolicyRequiresEncryptedId)
                }
            };
        }
        let requested = NameIdFormat::from_uri(&requested_uri);
        match requested {
            NameIdFormat::EmailAddress
            | NameIdFormat::Persistent
            | NameIdFormat::Transient
            | NameIdFormat::Entity
            | NameIdFormat::Kerberos
            | NameIdFormat::WindowsDomainQualifiedName
            | NameIdFormat::X509SubjectName => {
                if !is_name_id_format(issued_format, &requested_uri) {
                    return Err(SamlError::NameIdPolicyFormatMismatch {
                        requested,
                        issued: issued_format
                            .map(|uri| NameIdFormat::from_uri(&collapse_whitespace(uri))),
                    });
                }
            }
            NameIdFormat::Unspecified => {}
            NameIdFormat::Custom(_) => return Ok(()),
        }
        let Some(requested_namespace) = self.sp_name_qualifier() else {
            return Ok(());
        };
        let issued_namespace = match issued_sp_name_qualifier {
            // A persistent or pairwise transient identifier may omit the direct recipient's qualifier.
            None if requested == NameIdFormat::Unspecified
                && matches!(
                    name_id_format_in_effect(issued_format).as_str(),
                    name_id_format::PERSISTENT | name_id_format::TRANSIENT
                ) =>
            {
                recipient_entity_id
            }
            qualifier => qualifier,
        };
        if issued_namespace != Some(requested_namespace) {
            return Err(SamlError::Invalid(format!(
                "the NameIDPolicy requests SPNameQualifier {requested_namespace}, which the issued NameID must carry"
            )));
        }
        Ok(())
    }
}

/// A received `<SubjectConfirmation>` element.
///
/// [`crate::SsoSession::subject_confirmations`] and
/// [`RequestedSubject::confirmations`] return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectConfirmation {
    raw_xml: String,
}

impl SubjectConfirmation {
    pub(crate) fn from_raw_xml(raw_xml: impl Into<String>) -> Self {
        Self {
            raw_xml: raw_xml.into(),
        }
    }

    /// The `<SubjectConfirmation>` element as XML text.
    pub fn raw_xml(&self) -> &str {
        &self.raw_xml
    }
}

/// Subject requested by an `<AuthnRequest>` (Core §3.4.1).
///
/// In browser SSO, generating a success response returns [`SamlError::Invalid`]
/// unless the issued `NameId` has the requested `<NameID>` value, `Format`,
/// `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. An omitted
/// `Format` is `unspecified`. A `NameId` in the `NameIDPolicy` `Format` is
/// issued when that format differs from the requested one; the caller
/// decides that it names the same principal. A requested `<BaseID>`, or an
/// `<EncryptedID>` that was not decrypted, has no success response there. A
/// principal that is not the requested subject is answered with an error
/// status. `<SubjectConfirmation>` elements are not compared.
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

    pub(crate) fn ensure_strongly_matched_by(
        &self,
        value: &str,
        format: Option<&str>,
        qualifiers: OutboundNameIdQualifiers<'_>,
        policy: Option<&NameIdPolicy>,
    ) -> Result<(), SamlError> {
        let requested = match &self.identifier {
            RequestedSubjectIdentifier::NoIdentifier => return Ok(()),
            RequestedSubjectIdentifier::NameId(requested) => requested,
            RequestedSubjectIdentifier::BaseId => {
                return Err(SamlError::Invalid(
                    "the requested Subject has a BaseID, which an issued NameID cannot strongly match; answer with an error status"
                        .into(),
                ))
            }
            RequestedSubjectIdentifier::EncryptedId => {
                return Err(SamlError::Invalid(
                    "the requested Subject has an EncryptedID that was not decrypted, so the issued NameID cannot be matched to it; answer with an error status"
                        .into(),
                ))
            }
        };
        let issued_format = name_id_format_in_effect(format);
        let requested_format = requested.effective_format();
        let policy_format = policy
            .and_then(NameIdPolicy::format)
            .map(|policy_format| collapse_whitespace(policy_format.as_uri()));
        if issued_format != requested_format
            && policy_format.as_deref() == Some(issued_format.as_str())
        {
            return Ok(());
        }
        if requested_format == issued_format
            && requested.matches_value_and_qualifiers(value, qualifiers)
        {
            return Ok(());
        }
        Err(SamlError::Invalid(
            "the issued NameID does not strongly match the NameID of the requested Subject; issue that identifier or answer with an error status"
                .into(),
        ))
    }
}

fn name_id_format_in_effect(format: Option<&str>) -> String {
    format.map_or_else(
        || name_id_format::UNSPECIFIED.to_string(),
        collapse_whitespace,
    )
}
