use super::attributes::Attributes;
use super::extract::{
    attributes_from_extract, authn_sessions_from_extract, conditions_instants,
    entity_ids_from_value, name_id_format_from_uri, optional_request_id, required_str,
    subject_confirmations_from_extract,
};
use super::identifiers::{AssertionId, MessageId, SamlInstant};
use super::session::{AuthnSession, EMPTY_AUTHN_SESSION};
use super::subject::{NameId, Subject};
use super::{
    earliest_authn_session_expiration, LogoutSubject, ReplayKey, ReplayPolicy,
    SamlValidationContext,
};
use crate::config::EntityId;
use crate::error::{SamlError, TimeWindowField};
use crate::raw::FlowResult;
use crate::xml::{extract_with_limits, parse_saml_utc_date_time, ExtractorField, XmlLimits};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const REPLAY_EXPIRATION_FIELD: TimeWindowField = TimeWindowField::ReplayExpiration;

/// Parsed SSO response envelope.
#[derive(Debug, Clone)]
pub struct SsoResponse {
    response_id: MessageId,
    issue_instant: SamlInstant,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    raw_flow: FlowResult,
}

impl SsoResponse {
    /// Response ID.
    pub fn response_id(&self) -> &MessageId {
        &self.response_id
    }

    /// Response `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn issue_instant(&self) -> &SamlInstant {
        &self.issue_instant
    }

    /// Assertion issuer used by the current validated flow result.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
        self.in_response_to.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for SsoResponse {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let response_id = MessageId::try_new(required_str(&raw_flow.extract, "response.id")?)?;
        let issue_instant =
            issue_instant_from_extract(&raw_flow.extract, "response.issueInstant", "Response")?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        Ok(Self {
            response_id,
            issue_instant,
            issuer,
            in_response_to,
            raw_flow,
        })
    }
}

/// Assertion view extracted from an SSO session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    id: Option<AssertionId>,
    issuer: EntityId,
    subject: Subject,
}

impl Assertion {
    /// Create an assertion view.
    pub fn new(id: Option<AssertionId>, issuer: EntityId, subject: Subject) -> Self {
        Self {
            id,
            issuer,
            subject,
        }
    }

    /// Assertion ID, when extracted.
    pub fn id(&self) -> Option<&AssertionId> {
        self.id.as_ref()
    }

    /// Assertion issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// Assertion subject.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
}

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
#[derive(Debug, Clone)]
pub struct SsoSession {
    response_id: MessageId,
    response_issue_instant: SamlInstant,
    assertion_id: AssertionId,
    assertion_issue_instant: SamlInstant,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    subject: Subject,
    attributes: Attributes,
    authn_sessions: Vec<AuthnSession>,
    audience: Vec<EntityId>,
    not_before: Option<SamlInstant>,
    not_on_or_after: Option<SamlInstant>,
    sig_alg: Option<String>,
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

    /// Subject.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        self.subject.name_id()
    }

    /// Attributes.
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// Legacy singular view of `AuthnStatement` session data.
    ///
    /// This compatibility accessor returns the first statement in document
    /// order. For assertions containing multiple statements, use
    /// [`Self::authn_sessions`]. When no statement is present, it returns an
    /// immutable empty [`AuthnSession`].
    pub fn authn_session(&self) -> &AuthnSession {
        self.authn_sessions.first().unwrap_or(&EMPTY_AUTHN_SESSION)
    }

    /// Every `AuthnStatement` session tuple in XML document order.
    pub fn authn_sessions(&self) -> &[AuthnSession] {
        &self.authn_sessions
    }

    /// Audience restrictions.
    pub fn audience(&self) -> &[EntityId] {
        &self.audience
    }

    /// Conditions NotBefore.
    pub fn not_before(&self) -> Option<&SamlInstant> {
        self.not_before.as_ref()
    }

    /// Conditions NotOnOrAfter.
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }

    /// Verified detached Redirect or HTTP-POST-SimpleSign algorithm, when applicable.
    ///
    /// Embedded XML signatures are exposed separately through
    /// [`Self::verified_xml_signatures`] because a message can contain multiple
    /// verified signatures with different algorithms and coverage.
    pub fn sig_alg(&self) -> Option<&str> {
        self.sig_alg.as_deref()
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

    /// Assertion view.
    pub fn assertion(&self) -> Assertion {
        Assertion::new(
            Some(self.assertion_id.clone()),
            self.issuer.clone(),
            self.subject.clone(),
        )
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
            .authn_sessions
            .iter()
            .filter_map(AuthnSession::session_index)
            .cloned()
            .collect();
        Some(LogoutSubject::new(self.name_id().clone(), session_indexes))
    }

    /// Replay keys available from this validated SSO session.
    pub fn replay_keys(&self) -> Vec<ReplayKey> {
        let mut keys = vec![ReplayKey::ResponseId(self.response_id.clone())];
        let mut ids = crate::assertion_acceptance::assertion_ids(&self.raw_flow.saml_content)
            .unwrap_or_default();
        if !ids.iter().any(|id| id == self.assertion_id.as_str()) {
            ids.insert(0, self.assertion_id.as_str().to_string());
        }
        for id in ids {
            if let Ok(id) = AssertionId::try_new(id) {
                keys.push(ReplayKey::AssertionId(id));
            }
        }
        keys
    }

    /// Check and store this session's replay keys using the caller cache.
    ///
    /// This method is intended for typed inbound SSO facades. It should be
    /// called only after signature, issuer, audience, destination, recipient,
    /// `InResponseTo`, and time validation have already passed.
    ///
    /// The bearer assertion identifier is kept until
    /// `SubjectConfirmationData@NotOnOrAfter` plus skew. An earlier
    /// `Conditions` or `AuthnStatement` instant does not shorten it. The
    /// Response identifier still expires at the earliest bound. Every direct
    /// assertion identifier is stored. Another assertion uses its own bearer
    /// `NotOnOrAfter` when that attribute is present.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::TimeWindowInvalid`] when no valid replay
    /// expiration can be derived or a stored deadline has already passed.
    /// Nothing is stored in that case. Returns [`SamlError::ReplayDetected`]
    /// when any session replay key has already been seen. Cache
    /// implementations may also return storage-specific failures mapped to
    /// [`SamlError`].
    pub fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        let validation_now = validation.now_offset()?;
        let not_on_or_after_skew_ms = validation.clock_skew().not_on_or_after_millis();
        match validation.replay_policy() {
            ReplayPolicy::DisabledForCompatibility => Ok(()),
            ReplayPolicy::RequireCache(cache) => {
                let replays =
                    crate::assertion_acceptance::assertion_replays(&self.raw_flow.saml_content)?;
                let response_expires = system_time_from_offset(replay_deadline(
                    self.earliest_replay_instant()?,
                    validation_now,
                    not_on_or_after_skew_ms,
                )?)?;
                let assertion_expires = system_time_from_offset(replay_deadline(
                    self.assertion_replay_instant()?,
                    validation_now,
                    not_on_or_after_skew_ms,
                )?)?;
                cache.check_and_store(
                    ReplayKey::ResponseId(self.response_id.clone()),
                    response_expires,
                )?;
                cache.check_and_store(
                    ReplayKey::AssertionId(self.assertion_id.clone()),
                    assertion_expires,
                )?;
                for replay in replays {
                    if replay.id == self.assertion_id.as_str() {
                        continue;
                    }
                    let expires_at = match replay.bearer_not_on_or_after {
                        Some(instant) => system_time_from_offset(replay_deadline(
                            parse_replay_expiration(&instant)?,
                            validation_now,
                            not_on_or_after_skew_ms,
                        )?)?,
                        None => assertion_expires,
                    };
                    cache.check_and_store(
                        ReplayKey::AssertionId(AssertionId::try_new(replay.id)?),
                        expires_at,
                    )?;
                }
                Ok(())
            }
        }
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }

    fn earliest_replay_instant(&self) -> Result<OffsetDateTime, SamlError> {
        let mut candidates = Vec::with_capacity(3);
        if let Some(instant) = self.not_on_or_after() {
            candidates.push(parse_replay_expiration(instant.as_str())?);
        }
        if let Some(instant) = earliest_authn_session_expiration(
            self.authn_sessions
                .iter()
                .filter_map(AuthnSession::not_on_or_after)
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
        let fields = [
            ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
            ExtractorField::new(
                "subjectConfirmationData",
                &["SubjectConfirmation", "SubjectConfirmationData"],
            )
            .attrs(&["NotOnOrAfter"]),
        ];
        let mut expires_at = None;
        for confirmation in self.subject.confirmations() {
            let extracted =
                extract_with_limits(confirmation.raw_xml(), &fields, XmlLimits::default())?;
            if extracted.get_str("subjectConfirmation") != Some(BEARER_SUBJECT_CONFIRMATION_METHOD)
            {
                continue;
            }
            let Some(not_on_or_after) = extracted.get_str("subjectConfirmationData") else {
                continue;
            };
            let candidate = parse_replay_expiration(not_on_or_after)?;
            match expires_at {
                Some(current) if current >= candidate => {}
                Some(_) | None => expires_at = Some(candidate),
            }
        }
        Ok(expires_at)
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

fn system_time_from_offset(expires_at: OffsetDateTime) -> Result<SystemTime, SamlError> {
    let since_epoch = expires_at - OffsetDateTime::UNIX_EPOCH;
    let converted = if since_epoch.is_negative() {
        SystemTime::UNIX_EPOCH.checked_sub(since_epoch.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH.checked_add(since_epoch.unsigned_abs())
    };
    converted.ok_or(SamlError::TimeWindowInvalid {
        field: REPLAY_EXPIRATION_FIELD,
    })
}

fn parse_replay_expiration(value: &str) -> Result<OffsetDateTime, SamlError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| SamlError::TimeWindowInvalid {
        field: REPLAY_EXPIRATION_FIELD,
    })
}

impl TryFrom<FlowResult> for SsoSession {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        Self::try_from_with_verified_xml_signatures(raw_flow, Vec::new())
    }
}

impl SsoSession {
    pub(crate) fn try_from_with_verified_xml_signatures(
        raw_flow: FlowResult,
        verified_xml_signatures: Vec<VerifiedXmlSignature>,
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
        let name_id = NameId::with_qualifiers(
            required_str(&raw_flow.extract, "nameID")?,
            name_id_format,
            name_id_qualifier("nameIDQualifiers.nameQualifier"),
            name_id_qualifier("nameIDQualifiers.spNameQualifier"),
            name_id_qualifier("nameIDQualifiers.spProvidedId"),
        );
        let subject = Subject::new(
            name_id,
            subject_confirmations_from_extract(&raw_flow.extract),
        );
        let attributes = attributes_from_extract(&raw_flow.extract);
        let authn_sessions = authn_sessions_from_extract(&raw_flow.extract)?;
        let audience = entity_ids_from_value(raw_flow.extract.get("audience"))?;
        let (not_before, not_on_or_after) = conditions_instants(&raw_flow.extract)?;
        let sig_alg = raw_flow.sig_alg.clone();
        Ok(Self {
            response_id,
            response_issue_instant,
            assertion_id,
            assertion_issue_instant,
            issuer,
            in_response_to,
            subject,
            attributes,
            authn_sessions,
            audience,
            not_before,
            not_on_or_after,
            sig_alg,
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
