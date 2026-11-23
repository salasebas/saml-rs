use crate::artifact::{self, AnsweredArtifact, Artifact, ArtifactResolution, IssuedArtifacts};
use crate::browser::{ArtifactDelivery, Outbound};
use crate::config::{IdpDescriptor, SpDescriptor};
use crate::model::{AuthnRequest, Received, SamlValidationContext, SsoResponse};
use crate::soap::SoapChannel;
use std::time::SystemTime;

use super::idp::ResponseTransport;
use super::{IdentityProvider, RespondSso, SamlError, ServiceProvider, SsoOutcome};

impl IdentityProvider {
    /// Store the SAML protocol element `protocol_xml` for `service_provider`
    /// and return the artifact that refers to it.
    ///
    /// `endpoint_index` selects this identity provider's SOAP
    /// `ArtifactResolutionService`. The caller keeps `issued` and passes it to
    /// [`Self::answer_artifact_resolve`], which releases a `<Response>` only
    /// over a confidential channel and any other element over a mutually
    /// authenticated, integrity-protected one. Answer an `AuthnRequest` with
    /// [`Self::respond_sso_artifact`] instead, which builds the `<Response>`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Xml`] when `protocol_xml` is not one well-formed
    /// element or the element contains a processing instruction. Returns
    /// [`SamlError::ProtocolProfile`] when the element is outside the SAML
    /// protocol namespace, and another [`SamlError`] when metadata has no
    /// SOAP `ArtifactResolutionService` at `endpoint_index` or the artifact
    /// value is already outstanding.
    pub fn issue_artifact(
        &self,
        service_provider: &SpDescriptor,
        protocol_xml: &str,
        endpoint_index: u16,
        issued: &mut IssuedArtifacts,
    ) -> Result<Artifact, SamlError> {
        service_provider.ensure_valid_at(SystemTime::now())?;
        artifact::issue(
            &self.engine().metadata,
            service_provider,
            protocol_xml,
            endpoint_index,
            issued,
        )
    }

    /// Respond to a received AuthnRequest with an HTTP-Artifact.
    ///
    /// The `<Response>` is stored in `issued` for `sp`, and the returned
    /// browser action carries its artifact and RelayState to the assertion
    /// consumer. Send that action with
    /// [`Outbound::headers`](crate::Outbound::headers). Pass `issued` to
    /// [`Self::answer_artifact_resolve`] when the service provider resolves
    /// the artifact.
    ///
    /// `outcome` says what the response reports, as for
    /// [`Self::respond_sso`]. An [`SsoOutcome::Failure`] is stored and
    /// delivered the same way.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the service provider publishes no
    /// HTTP-Artifact assertion consumer the request allows, this identity
    /// provider's metadata has no SOAP `ArtifactResolutionService` at the
    /// delivery's index, or [`Self::respond_sso`] would fail, including
    /// [`SamlError::Invalid`] for an [`SsoOutcome::Failure`] with a top-level
    /// `Success` status. Returns [`SamlError::ProtocolProfile`] when
    /// [`RespondSso::relay_state`] is set and `request` carried `RelayState`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     ArtifactDelivery, AuthnRequest, IdentityProvider, IssuedArtifacts, NameId, Received,
    ///     RespondSso, SpDescriptor, SsoAssertion,
    /// };
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<AuthnRequest>,
    /// #     name_id: NameId,
    /// #     issued: &mut IssuedArtifacts,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.respond_sso_artifact(
    ///     sp,
    ///     request,
    ///     SsoAssertion::new(name_id),
    ///     RespondSso::artifact(ArtifactDelivery::redirect(0)),
    ///     issued,
    /// )?;
    ///
    /// let location = response.redirect_url()?;
    /// # let _ = location;
    /// # Ok(()) }
    /// ```
    pub fn respond_sso_artifact(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        outcome: impl Into<SsoOutcome>,
        options: RespondSso<ArtifactDelivery>,
        issued: &mut IssuedArtifacts,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, issued);
        self.issue_sso(
            sp,
            Some(request),
            &outcome.into(),
            options.delivered(transport),
        )
    }

    /// Initiate IdP-initiated SSO with an HTTP-Artifact.
    ///
    /// The artifact goes to the service provider's default assertion
    /// consumer, which must use HTTP-Artifact. `outcome` says what the
    /// unsolicited response reports, as for [`Self::initiate_sso`].
    ///
    /// # Errors
    ///
    /// Returns the errors documented on [`Self::respond_sso_artifact`] and
    /// [`Self::initiate_sso`].
    pub fn initiate_sso_artifact(
        &self,
        sp: &SpDescriptor,
        outcome: impl Into<SsoOutcome>,
        options: RespondSso<ArtifactDelivery>,
        issued: &mut IssuedArtifacts,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, issued);
        self.issue_sso(sp, None, &outcome.into(), options.delivered(transport))
    }

    /// Answer `ArtifactResolve` with `ArtifactResponse`.
    ///
    /// The protocol message is included only when `presenter` is the service
    /// provider the artifact was issued to and `channel` supplies the protection
    /// that message requires. [`AnsweredArtifact::release`] says whether the
    /// response includes the message. An unknown artifact, a different
    /// destination or presenter, or insufficient channel protection gets
    /// `Success` without the message. An unsupported newer version gets
    /// `VersionMismatch`, with `RequestVersionTooHigh` for a newer major version.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `request_envelope` cannot be read as a SOAP
    /// 1.1 envelope. Returns [`SamlError::ProtocolProfile`] when the body is
    /// not one `ArtifactResolve`, the request lacks exactly one `Artifact`
    /// value or has a second `Issuer`, or the required `ID`, `Version`, or UTC
    /// `IssueInstant` fails validation. A version below 2.0 also returns
    /// [`SamlError::ProtocolProfile`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    ///
    /// use saml_rs::{
    ///     ArtifactResolutionService, EndpointUrl, EntityId, IdentityProvider, IdpConfig,
    ///     IdpDescriptor, InMemoryReplayCache, IssuedArtifacts, MetadataTrustPolicy, ReplayPolicy,
    ///     SamlValidationContext, ServiceProvider, SoapChannel, SpConfig, SpDescriptor,
    ///     SsoEndpoint,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// # if cfg!(not(crypto)) { return Ok(()); }
    /// let service = ArtifactResolutionService::new(
    ///     0,
    ///     EndpointUrl::try_new("https://idp.example.com/artifact")?,
    /// );
    /// let idp = IdentityProvider::new(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?, SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///         .artifact_resolution_service(service)
    ///         .build()?,
    /// );
    /// let sp = ServiceProvider::new(
    ///     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?, saml_rs::AcsEndpoint::post("https://sp.example.com/acs")?)
    ///         .build()?,
    /// );
    /// let sp_descriptor = SpDescriptor::from_metadata_xml(
    ///     EntityId::try_new("https://sp.example.com/metadata")?,
    ///     sp.metadata_xml(),
    ///     MetadataTrustPolicy::AllowUnsigned,
    /// )?;
    /// let idp_descriptor = IdpDescriptor::from_metadata_xml(
    ///     EntityId::try_new("https://idp.example.com/metadata")?,
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::AllowUnsigned,
    /// )?;
    /// let message = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">artifact-message</samlp:LogoutRequest>"#;
    /// let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60));
    /// let artifact = idp.issue_artifact(&sp_descriptor, message, 0, &mut issued)?;
    /// let channel = SoapChannel::mutually_authenticated_confidential();
    /// let mut replay = InMemoryReplayCache::new();
    /// let resolution = sp.resolve_artifact(
    ///     &idp_descriptor,
    ///     &artifact,
    ///     channel,
    ///     SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut replay))
    ///         .with_replay_retention(Duration::from_secs(10 * 60)),
    /// )?;
    /// let answer = idp.answer_artifact_resolve(
    ///     &sp_descriptor,
    ///     resolution.request().envelope(),
    ///     &mut issued,
    ///     channel,
    /// )?;
    /// let resolved = resolution.finish(answer.response().envelope())?;
    /// assert!(resolved.xml().contains("artifact-message"));
    /// # Ok(()) }
    /// ```
    pub fn answer_artifact_resolve(
        &self,
        presenter: &SpDescriptor,
        request_envelope: &str,
        issued: &mut IssuedArtifacts,
        channel: SoapChannel,
    ) -> Result<AnsweredArtifact, SamlError> {
        presenter.ensure_valid_at(SystemTime::now())?;
        artifact::answer(
            &self.engine().metadata,
            presenter,
            request_envelope,
            issued,
            channel,
            &self.engine().setting,
        )
    }
}

impl ServiceProvider {
    /// Send `ArtifactResolve` to the identity provider's `ArtifactResolutionService`.
    ///
    /// The endpoint comes from the artifact's endpoint index in the identity
    /// provider metadata. Post [`ArtifactResolution::request`] with the
    /// deployment's HTTP client, then [`ArtifactResolution::finish`] with the
    /// SOAP response. TLS and HTTP authentication stay with that client;
    /// `channel` records the protection it provides, which must be mutual
    /// authentication, integrity protection, and confidentiality.
    ///
    /// The artifact is single-use. With [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache),
    /// a successful call stores [`ReplayKey::Artifact`](crate::ReplayKey::Artifact)
    /// until `validation` time plus
    /// [`SamlValidationContext::with_replay_retention`], which is then
    /// required. Choose a retention longer than the identity provider keeps
    /// the artifact. A later call with the same artifact fails, even when
    /// this resolution did not complete. [`ReplayPolicy::Disabled`](crate::ReplayPolicy::Disabled)
    /// skips the check; the identity provider still returns the message only
    /// once.
    ///
    /// The artifact is stored before the identity provider confirms it, so a
    /// forged `SAMLart` value also takes an entry. Give a cache with an entry
    /// limit room for every artifact received during the retention, or pass a
    /// separate cache here so a flood of artifacts cannot fill the cache that
    /// [`Self::finish_sso`] uses.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::SoapChannelProtection`] when `channel` lacks one
    /// of the three properties, [`SamlError::ReplayDetected`] for an artifact
    /// already stored, [`SamlError::ReplayCacheUnavailable`] when the cache
    /// cannot store it, for example because it is full,
    /// [`SamlError::TimeWindowInvalid`] when a replay cache is passed without
    /// a retention, and another [`SamlError`] when the artifact
    /// was not issued by `identity_provider` or metadata has no SOAP
    /// resolution service at the artifact's index.
    pub fn resolve_artifact(
        &self,
        identity_provider: &IdpDescriptor,
        artifact: &Artifact,
        channel: SoapChannel,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<ArtifactResolution, SamlError> {
        identity_provider.ensure_valid_at(validation.now())?;
        let entity_id = self
            .engine()
            .metadata
            .as_metadata()
            .entity_id()
            .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?;
        artifact::resolve(
            entity_id,
            identity_provider,
            artifact,
            channel,
            &mut validation,
            &self.engine().setting,
        )
    }
}
