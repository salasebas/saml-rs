use super::attributes::Attributes;
use super::audience_restriction::AudienceRestriction;
use super::authn_statement::AuthnStatement;
use super::extract::{
    assertion_subject_name_id, attributes_from_extract, audience_restrictions_from_extract,
    authn_statements_from_extract, conditions_instants, optional_request_id,
    required_saml_utc_instant, required_str, subject_confirmations_from_extract,
};
use super::identifiers::{AssertionId, MessageId, SamlInstant};
use super::subject::{NameId, SubjectConfirmation};
use super::subject_identifier::{PairwiseId, SubjectId};
use super::validation::system_time_from_offset_datetime;
use super::{
    earliest_authn_session_expiration, LogoutSubject, RelayState, ReplayKey, ReplayPolicy,
    SamlValidationContext,
};
use crate::assertion_acceptance::{assertion_replays, latest_bearer_not_on_or_after};
use crate::config::EntityId;
use crate::error::{SamlError, TimeWindowField};
use crate::flow::FlowResult;
use crate::xml::fields::{login_response, response};
use crate::xml::{dom, parse_saml_utc_instant, XmlLimits};
use time::{Duration, OffsetDateTime};

const REPLAY_EXPIRATION_FIELD: TimeWindowField = TimeWindowField::ReplayExpiration;

/// The SAML `<Response>` of a Web Browser SSO login, as a message type.
///
/// It names the message in [`crate::Inbound`] and [`crate::Outbound`]. It has
/// no values: a service provider receives
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
/// The assertion fields come from the first bearer assertion with an
/// `AuthnStatement`, in document order. If no bearer assertion has one, the
/// fields come from the first bearer assertion.
#[derive(Debug, Clone)]
pub struct SsoSession {
    response_id: MessageId,
    response_issue_instant: SamlInstant,
    assertion_id: AssertionId,
    assertion_issue_instant: SamlInstant,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    relay_state: Option<RelayState>,
    name_id: Option<NameId>,
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
    /// the caller interprets by prior agreement. A caller that redirects to a
    /// URL taken from this value sanitizes the URL first.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// The `NameID` of the assertion `Subject`, or `None` when the `Subject`
    /// has only `SubjectConfirmation` elements.
    ///
    /// Without a `NameID`, the application identifies the principal from
    /// [`Self::attributes`], and the session has no [`Self::logout_subject`].
    pub fn name_id(&self) -> Option<&NameId> {
        self.name_id.as_ref()
    }

    /// The `SubjectConfirmation` elements of the assertion `Subject`, in
    /// document order.
    pub fn subject_confirmations(&self) -> &[SubjectConfirmation] {
        &self.subject_confirmations
    }

    /// Attributes, one for each `Name` and `NameFormat` pair in document
    /// order, with the values of every `<Attribute>` that has that pair.
    ///
    /// The `Name` is compared exactly. The `NameFormat` is compared and
    /// reported after XML whitespace collapse. An `<Attribute>` without
    /// `NameFormat` has the same identity as one with the `unspecified`
    /// format. The attribute reports the `NameFormat` of its first element.
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// The `subject-id` attribute of the assertion, when it has one.
    ///
    /// This is the attribute named
    /// [`crate::constants::attribute_name::SUBJECT_ID`] with the `uri`
    /// `NameFormat`, the unspecified one, or none. An attribute with that name
    /// and another `NameFormat` is a different attribute. Leading and trailing
    /// XML whitespace of the value is removed.
    ///
    /// The scope is not checked against the issuer. Before you trust the
    /// value, use [`Self::scoped_attribute_violations`] or another policy to
    /// confirm that [`Self::issuer`] may assert identifiers in [`SubjectId::scope`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ProtocolProfile`] when those attributes together
    /// do not have exactly one value, or the value is not `uniqueID@scope`.
    pub fn subject_id(&self) -> Result<Option<SubjectId>, SamlError> {
        SubjectId::received(&self.attributes)
    }

    /// The `pairwise-id` attribute of the assertion, when it has one.
    ///
    /// This is the attribute named
    /// [`crate::constants::attribute_name::PAIRWISE_ID`] with the `uri`
    /// `NameFormat`, the unspecified one, or none. An attribute with that name
    /// and another `NameFormat` is a different attribute. Leading and trailing
    /// XML whitespace of the value is removed.
    ///
    /// The scope is not checked against the issuer. Before you trust the
    /// value, use [`Self::scoped_attribute_violations`] or another policy to
    /// confirm that [`Self::issuer`] may assert identifiers in [`PairwiseId::scope`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ProtocolProfile`] when those attributes together
    /// do not have exactly one value, or the value is not `uniqueID@scope`.
    pub fn pairwise_id(&self) -> Result<Option<PairwiseId>, SamlError> {
        PairwiseId::received(&self.attributes)
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
    ///
    /// An accepted value is a UTC `xs:dateTime` ending in `Z`, normalized
    /// according to XML Schema whitespace rules.
    pub fn not_before(&self) -> Option<&SamlInstant> {
        self.not_before.as_ref()
    }

    /// The `NotOnOrAfter` of the assertion `Conditions`, when present.
    ///
    /// An accepted value is a UTC `xs:dateTime` ending in `Z`, normalized
    /// according to XML Schema whitespace rules. Use
    /// [`Self::session_not_on_or_after`] for the application session deadline.
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }

    /// The earliest `SessionNotOnOrAfter` in the consumed assertion.
    ///
    /// Returns `None` when its authentication statements specify no deadline.
    /// Use this deadline to cap the application's session lifetime. The value
    /// retains the precision sent by the identity provider, before clock skew.
    pub fn session_not_on_or_after(&self) -> Option<&SamlInstant> {
        // Acceptance restricts these values to fixed-width RFC 3339 UTC date
        // and time fields. Removing Z lets a whole second sort before fractions.
        self.authn_statements
            .iter()
            .filter_map(AuthnStatement::session_not_on_or_after)
            .min_by_key(|deadline| deadline.as_str().trim_end_matches('Z'))
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
    /// order. Returns `None` when the assertion has no `NameID` or its value
    /// is blank.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, SamlError, ServiceProvider, SsoSession, StartSlo};
    ///
    /// # fn logout(
    /// #     sp: &ServiceProvider,
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
        let name_id = self
            .name_id()
            .filter(|name_id| !name_id.value().trim().is_empty())?;
        let session_indexes = self
            .authn_statements
            .iter()
            .filter_map(AuthnStatement::session_index)
            .cloned();
        Some(LogoutSubject::new(name_id.clone()).with_session_indexes(session_indexes))
    }

    pub(crate) fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
        limits: XmlLimits,
    ) -> Result<(), SamlError> {
        let validation_now = validation.now_offset()?;
        let not_on_or_after_skew_ms = validation.clock_skew().not_on_or_after_millis();
        match validation.replay_policy() {
            ReplayPolicy::NoCache => Ok(()),
            ReplayPolicy::RequireCache(cache) => {
                let replays = assertion_replays(&self.raw_flow.saml_content, limits)?;
                let bearer_expires = self.bearer_subject_confirmation_expires_at(limits)?;
                let earliest = self.earliest_replay_instant(bearer_expires)?;
                let response_expires = system_time_from_offset_datetime(replay_deadline(
                    earliest,
                    validation_now,
                    not_on_or_after_skew_ms,
                )?)?;
                let assertion_expires = system_time_from_offset_datetime(replay_deadline(
                    bearer_expires.unwrap_or(earliest),
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
                    let bearer_expires = match replay.bearer_not_on_or_after {
                        Some(instant) => bearer_confirmable_until(
                            &instant,
                            validation_now,
                            not_on_or_after_skew_ms,
                        )?,
                        None => None,
                    };
                    let expires_at = match bearer_expires {
                        Some(instant) => system_time_from_offset_datetime(instant)?,
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

    fn earliest_replay_instant(
        &self,
        bearer_expires: Option<OffsetDateTime>,
    ) -> Result<OffsetDateTime, SamlError> {
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
        if let Some(instant) = bearer_expires {
            candidates.push(instant);
        }
        candidates
            .into_iter()
            .min()
            .ok_or(SamlError::TimeWindowInvalid {
                field: REPLAY_EXPIRATION_FIELD,
            })
    }

    fn bearer_subject_confirmation_expires_at(
        &self,
        limits: XmlLimits,
    ) -> Result<Option<OffsetDateTime>, SamlError> {
        let confirmations = self
            .subject_confirmations
            .iter()
            .map(|confirmation| dom::parse_fragment_with_limits(confirmation.raw_xml(), limits))
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
    let expires_at = shifted_replay_expiration(raw_expires_at, not_on_or_after_skew_ms)?;
    if validation_now >= expires_at {
        return Err(SamlError::TimeWindowInvalid {
            field: REPLAY_EXPIRATION_FIELD,
        });
    }
    Ok(expires_at)
}

fn bearer_confirmable_until(
    latest_not_on_or_after: &str,
    validation_now: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let Some(raw_expires_at) = parse_saml_utc_instant(latest_not_on_or_after) else {
        return Ok(None);
    };
    let expires_at = shifted_replay_expiration(raw_expires_at, not_on_or_after_skew_ms)?;
    Ok((validation_now < expires_at).then_some(expires_at))
}

fn shifted_replay_expiration(
    raw_expires_at: OffsetDateTime,
    not_on_or_after_skew_ms: i64,
) -> Result<OffsetDateTime, SamlError> {
    raw_expires_at
        .checked_add(Duration::milliseconds(not_on_or_after_skew_ms))
        .ok_or(SamlError::TimeWindowInvalid {
            field: REPLAY_EXPIRATION_FIELD,
        })
}

fn parse_replay_expiration(value: &str) -> Result<OffsetDateTime, SamlError> {
    parse_saml_utc_instant(value).ok_or(SamlError::TimeWindowInvalid {
        field: REPLAY_EXPIRATION_FIELD,
    })
}

impl SsoSession {
    pub(crate) fn try_from_with_verified_xml_signatures(
        raw_flow: FlowResult,
        verified_xml_signatures: Vec<VerifiedXmlSignature>,
        relay_state: Option<RelayState>,
    ) -> Result<Self, SamlError> {
        let response_id = MessageId::try_new(required_str(&raw_flow.extract, response::ID)?)?;
        let response_issue_instant = required_saml_utc_instant(
            raw_flow.extract.get_str(response::ISSUE_INSTANT),
            "Response",
            "IssueInstant",
        )?;
        let assertion_id = AssertionId::try_new(required_str(
            &raw_flow.extract,
            login_response::ASSERTION_ID,
        )?)?;
        let assertion_issue_instant = required_saml_utc_instant(
            raw_flow
                .extract
                .get_str(login_response::ASSERTION_ISSUE_INSTANT),
            "Assertion",
            "IssueInstant",
        )?;
        let issuer = EntityId::try_new(required_str(
            &raw_flow.extract,
            login_response::ASSERTION_ISSUER,
        )?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, response::IN_RESPONSE_TO)?;
        let name_id = assertion_subject_name_id(&raw_flow.extract)?;
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
