use super::attributes::Attributes;
use super::audience_restriction::AudienceRestriction;
use super::authn_statement::AuthnStatement;
use super::extract::{
    attributes_from_extract, audience_restrictions_from_extract, authn_statements_from_extract,
    conditions_instants, name_id_format_from_uri, optional_request_id, required_str,
    subject_confirmations_from_extract,
};
use super::identifiers::{AssertionId, MessageId, SamlInstant};
use super::subject::{NameId, SubjectConfirmation};
use super::validation::system_time_from_offset_datetime;
use super::{
    earliest_authn_session_expiration, LogoutSubject, RelayState, ReplayKey, ReplayPolicy,
    SamlValidationContext,
};
use crate::assertion_acceptance::latest_bearer_not_on_or_after;
use crate::config::EntityId;
use crate::error::{SamlError, TimeWindowField};
use crate::flow::FlowResult;
use crate::xml::{dom, parse_saml_utc_date_time, XmlLimits};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

const REPLAY_EXPIRATION_FIELD: TimeWindowField = TimeWindowField::ReplayExpiration;

/// The SAML `<Response>` of a Web Browser SSO or ECP login, as a message type.
///
/// It names the message in [`crate::Inbound`], [`crate::Outbound`], and
/// [`crate::PaosHttpResponse`]. It has no values: a service provider receives
/// the accepted response as an [`SsoSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoResponse {}

/// Authenticated SAML objects covered by one verified embedded XML signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedXmlSignatureCoverage {
    /// The signature covers the top-level SAML `Response` element.
    ResponseRoot,
    /// The signature directly covers the Assertion consumed for this session.
    ConsumedAssertion,
    /// The signature covers both the Response root and the consumed Assertion.
    ResponseRootAndConsumedAssertion,
}

/// Evidence from one successfully verified embedded XML signature.
///
/// The algorithm URI comes from the exact `SignatureMethod` belonging to the
/// signature node that the XML verifier reported as valid. This evidence does
/// not contain raw XML, signature bytes, or certificate material, and exposing
/// it does not apply an application algorithm allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedXmlSignature {
    algorithm_uri: String,
    coverage: VerifiedXmlSignatureCoverage,
}

impl VerifiedXmlSignature {
    pub(crate) fn from_verified_coverage(
        algorithm_uri: String,
        response_covered: bool,
        assertion_directly_covered: bool,
    ) -> Option<Self> {
        let coverage = match (response_covered, assertion_directly_covered) {
            (true, true) => VerifiedXmlSignatureCoverage::ResponseRootAndConsumedAssertion,
            (true, false) => VerifiedXmlSignatureCoverage::ResponseRoot,
            (false, true) => VerifiedXmlSignatureCoverage::ConsumedAssertion,
            (false, false) => return None,
        };
        Some(Self {
            algorithm_uri,
            coverage,
        })
    }

    /// Exact XML-DSig `SignatureMethod@Algorithm` URI for this verified signature.
    pub fn algorithm_uri(&self) -> &str {
        &self.algorithm_uri
    }

    /// Authenticated SAML object coverage established by this signature's
    /// verified references.
    pub fn coverage(&self) -> VerifiedXmlSignatureCoverage {
        self.coverage
    }
}

/// Parsed SSO login session.
///
/// The assertion fields come from the first assertion of the response that
/// carries a bearer `SubjectConfirmation`, in document order.
#[derive(Debug, Clone)]
pub struct SsoSession {
    response_id: MessageId,
    response_issue_instant: SamlInstant,
    assertion_id: AssertionId,
    assertion_issue_instant: SamlInstant,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    relay_state: Option<RelayState>,
    name_id: NameId,
    subject_confirmations: Vec<SubjectConfirmation>,
    attributes: Attributes,
    authn_statements: Vec<AuthnStatement>,
    audience_restrictions: Vec<AudienceRestriction>,
    not_before: Option<SamlInstant>,
    not_on_or_after: Option<SamlInstant>,
    binding_signature_algorithm_uri: Option<String>,
    verified_xml_signatures: Vec<VerifiedXmlSignature>,
    raw_flow: FlowResult,
}

impl SsoSession {
    /// Response ID.
    pub fn response_id(&self) -> &MessageId {
        &self.response_id
    }

    /// Response `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn response_issue_instant(&self) -> &SamlInstant {
        &self.response_issue_instant
    }

    /// Assertion ID.
    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    /// Selected assertion `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn assertion_issue_instant(&self) -> &SamlInstant {
        &self.assertion_issue_instant
    }

    /// Assertion issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
        self.in_response_to.as_ref()
    }

    /// RelayState received with the response.
    ///
    /// When the request carried RelayState, this is the same value. When it
    /// carried none, this is whatever the identity provider supplied, which
    /// the caller interprets by prior agreement.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// The `NameID` of the assertion `Subject`.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// The `SubjectConfirmation` elements of the assertion `Subject`, in
    /// document order.
    pub fn subject_confirmations(&self) -> &[SubjectConfirmation] {
        &self.subject_confirmations
    }

    /// Attributes, one for each `Name` and `NameFormat` pair in document
    /// order, with the values of every `<Attribute>` that has that pair.
    ///
    /// An `<Attribute>` without `NameFormat` has the same identity as one with
    /// the `unspecified` format. The attribute reports the `NameFormat` of its
    /// first element.
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// The `<AuthnStatement>` elements of the assertion, in document order.
    ///
    /// The slice is empty when the assertion has no `AuthnStatement`.
    pub fn authn_statements(&self) -> &[AuthnStatement] {
        &self.authn_statements
    }

    /// The `<AudienceRestriction>` elements of the assertion `Conditions`, in
    /// document order.
    ///
    /// Each value keeps the audiences of one restriction. The assertion is
    /// addressed to a relying party that is in every restriction. The slice
    /// is empty when the assertion has no `AudienceRestriction`.
    pub fn audience_restrictions(&self) -> &[AudienceRestriction] {
        &self.audience_restrictions
    }

    /// The `NotBefore` of the assertion `Conditions`, when present.
    pub fn not_before(&self) -> Option<&SamlInstant> {
        self.not_before.as_ref()
    }

    /// The `NotOnOrAfter` of the assertion `Conditions`, when present.
    ///
    /// The `SessionNotOnOrAfter` of a statement is
    /// [`AuthnStatement::session_not_on_or_after`].
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }

    /// The `SigAlg` URI of the verified binding signature, when the response
    /// carried one.
    ///
    /// A binding signature travels as a parameter next to the message: the
    /// HTTP-POST-SimpleSign `Signature` parameter. Every other response
    /// returns `None`, including one signed only inside the XML. Those
    /// signatures are in [`Self::verified_xml_signatures`].
    pub fn binding_signature_algorithm_uri(&self) -> Option<&str> {
        self.binding_signature_algorithm_uri.as_deref()
    }

    /// Successfully verified embedded XML signatures that authenticate this
    /// session's Response root or consumed Assertion.
    ///
    /// Each item is bound to one exact verifier-approved signature node and
    /// its verified references. Invalid, untrusted, malformed, or unrelated
    /// signatures are not included. The view preserves distinct signatures;
    /// it does not select a signature by XML order. Applications may inspect
    /// the reported algorithm URIs to enforce their own allowlist.
    pub fn verified_xml_signatures(&self) -> &[VerifiedXmlSignature] {
        &self.verified_xml_signatures
    }

    /// Subject data suitable for issuing Single Logout.
    ///
    /// Every present `SessionIndex` is included in `AuthnStatement` document
    /// order.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, Saml, SamlError, SsoSession, StartSlo};
    ///
    /// # fn logout(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     session: &SsoSession,
    /// # ) -> Result<(), SamlError> {
    /// let subject = session
    ///     .logout_subject()
    ///     .ok_or_else(|| SamlError::Invalid("missing logout subject".into()))?;
    /// let started = sp.start_slo(idp, subject, StartSlo::redirect())?;
    ///
    /// let redirect_url = started.outbound.redirect_url()?;
    /// # let _ = redirect_url;
    /// # Ok(()) }
    /// ```
    pub fn logout_subject(&self) -> Option<LogoutSubject> {
        if self.name_id().value().trim().is_empty() {
            return None;
        }
        let session_indexes = self
            .authn_statements
            .iter()
            .filter_map(AuthnStatement::session_index)
            .cloned();
        Some(LogoutSubject::new(self.name_id().clone()).with_session_indexes(session_indexes))
    }

    /// Check and store this session's replay keys using the caller cache.
    ///
    /// Call it only after signature, issuer, audience, destination, recipient,
    /// `InResponseTo`, and time validation have passed.
    ///
    /// The bearer assertion identifier is kept until the latest bearer
    /// `SubjectConfirmationData@NotOnOrAfter` plus skew. A value that does not
    /// parse as an instant counts only when no other bearer value does. An
    /// earlier `Conditions` or `AuthnStatement` instant does not shorten it.
    /// The Response identifier still expires at the earliest bound. Every
    /// direct assertion identifier is stored. Another assertion uses its own
    /// bearer `NotOnOrAfter`, chosen the same way, when that attribute is
    /// present.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::TimeWindowInvalid`] when no valid replay
    /// expiration can be derived or a stored deadline has already passed.
    /// Nothing is stored in that case. Returns [`SamlError::ReplayDetected`]
    /// when any session replay key has already been seen. Cache
    /// implementations may also return storage-specific failures mapped to
    /// [`SamlError`].
    pub(crate) fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        let validation_now = validation.now_offset()?;
        let not_on_or_after_skew_ms = validation.clock_skew().not_on_or_after_millis();
        match validation.replay_policy() {
            ReplayPolicy::Disabled => Ok(()),
            ReplayPolicy::RequireCache(cache) => {
                let replays =
                    crate::assertion_acceptance::assertion_replays(&self.raw_flow.saml_content)?;
                let response_expires = system_time_from_offset_datetime(replay_deadline(
                    self.earliest_replay_instant()?,
                    validation_now,
                    not_on_or_after_skew_ms,
                )?)?;
                let assertion_expires = system_time_from_offset_datetime(replay_deadline(
                    self.assertion_replay_instant()?,
                    validation_now,
                    not_on_or_after_skew_ms,
                )?)?;
                cache.check_and_store(
                    ReplayKey::SsoResponse(self.response_id.clone()),
                    response_expires,
                )?;
                cache.check_and_store(
                    ReplayKey::Assertion(self.assertion_id.clone()),
                    assertion_expires,
                )?;
                for replay in replays {
                    if replay.id == self.assertion_id.as_str() {
                        continue;
                    }
                    let expires_at = match replay.bearer_not_on_or_after {
                        Some(instant) => system_time_from_offset_datetime(replay_deadline(
                            parse_replay_expiration(&instant)?,
                            validation_now,
                            not_on_or_after_skew_ms,
                        )?)?,
                        None => assertion_expires,
                    };
                    cache.check_and_store(
                        ReplayKey::Assertion(AssertionId::try_new(replay.id)?),
                        expires_at,
                    )?;
                }
                Ok(())
            }
        }
    }

    fn earliest_replay_instant(&self) -> Result<OffsetDateTime, SamlError> {
        let mut candidates = Vec::with_capacity(3);
        if let Some(instant) = self.not_on_or_after() {
            candidates.push(parse_replay_expiration(instant.as_str())?);
        }
        if let Some(instant) = earliest_authn_session_expiration(
            self.authn_statements
                .iter()
                .filter_map(AuthnStatement::session_not_on_or_after)
                .map(SamlInstant::as_str),
            REPLAY_EXPIRATION_FIELD,
        )? {
            candidates.push(instant);
        }
        if let Some(instant) = self.bearer_subject_confirmation_expires_at()? {
            candidates.push(instant);
        }
        candidates
            .into_iter()
            .min()
            .ok_or(SamlError::TimeWindowInvalid {
                field: REPLAY_EXPIRATION_FIELD,
            })
    }

    fn assertion_replay_instant(&self) -> Result<OffsetDateTime, SamlError> {
        if let Some(instant) = self.bearer_subject_confirmation_expires_at()? {
            return Ok(instant);
        }
        self.earliest_replay_instant()
    }

    fn bearer_subject_confirmation_expires_at(&self) -> Result<Option<OffsetDateTime>, SamlError> {
        let confirmations = self
            .subject_confirmations
            .iter()
            .map(|confirmation| {
                dom::parse_fragment_with_limits(confirmation.raw_xml(), XmlLimits::default())
            })
            .collect::<Result<Vec<_>, _>>()?;
        latest_bearer_not_on_or_after(confirmations.iter().map(|document| &document.root))
            .as_deref()
            .map(parse_replay_expiration)
            .transpose()
    }
}

fn replay_deadline(
    raw_expires_at: OffsetDateTime,
    validation_now: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<OffsetDateTime, SamlError> {
    let expires_at = raw_expires_at
        .checked_add(Duration::milliseconds(not_on_or_after_skew_ms))
        .ok_or(SamlError::TimeWindowInvalid {
            field: REPLAY_EXPIRATION_FIELD,
        })?;
    if validation_now >= expires_at {
        return Err(SamlError::TimeWindowInvalid {
            field: REPLAY_EXPIRATION_FIELD,
        });
    }
    Ok(expires_at)
}

fn parse_replay_expiration(value: &str) -> Result<OffsetDateTime, SamlError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| SamlError::TimeWindowInvalid {
        field: REPLAY_EXPIRATION_FIELD,
    })
}

impl SsoSession {
    pub(crate) fn try_from_with_verified_xml_signatures(
        raw_flow: FlowResult,
        verified_xml_signatures: Vec<VerifiedXmlSignature>,
        relay_state: Option<RelayState>,
    ) -> Result<Self, SamlError> {
        let response_id = MessageId::try_new(required_str(&raw_flow.extract, "response.id")?)?;
        let response_issue_instant =
            issue_instant_from_extract(&raw_flow.extract, "response.issueInstant", "Response")?;
        let assertion_id = AssertionId::try_new(required_str(&raw_flow.extract, "assertion.id")?)?;
        let assertion_issue_instant =
            issue_instant_from_extract(&raw_flow.extract, "assertion.issueInstant", "Assertion")?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        let name_id_format = raw_flow
            .extract
            .get_str("nameIDFormat")
            .map(name_id_format_from_uri);
        let name_id_qualifier = |field: &str| raw_flow.extract.get_str(field).map(str::to_string);
        let name_id = NameId::received(
            required_str(&raw_flow.extract, "nameID")?,
            name_id_format,
            name_id_qualifier("nameIDQualifiers.nameQualifier"),
            name_id_qualifier("nameIDQualifiers.spNameQualifier"),
            name_id_qualifier("nameIDQualifiers.spProvidedId"),
        );
        let subject_confirmations = subject_confirmations_from_extract(&raw_flow.extract);
        let attributes = attributes_from_extract(&raw_flow.extract)?;
        let authn_statements =
            authn_statements_from_extract(&raw_flow.extract, &raw_flow.saml_content)?;
        let audience_restrictions = audience_restrictions_from_extract(&raw_flow.extract)?;
        let (not_before, not_on_or_after) = conditions_instants(&raw_flow.extract)?;
        let binding_signature_algorithm_uri = raw_flow.sig_alg.clone();
        Ok(Self {
            response_id,
            response_issue_instant,
            assertion_id,
            assertion_issue_instant,
            issuer,
            in_response_to,
            relay_state,
            name_id,
            subject_confirmations,
            attributes,
            authn_statements,
            audience_restrictions,
            not_before,
            not_on_or_after,
            binding_signature_algorithm_uri,
            verified_xml_signatures,
            raw_flow,
        })
    }
}

fn issue_instant_from_extract(
    extract: &crate::util::Value,
    path: &str,
    element: &str,
) -> Result<SamlInstant, SamlError> {
    let issue_instant = extract.get_str(path).ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "{element} is missing required unqualified attribute IssueInstant"
        ))
    })?;
    let issue_instant = parse_saml_utc_date_time(issue_instant).ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "{element} IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
        ))
    })?;
    SamlInstant::try_new(issue_instant)
}
