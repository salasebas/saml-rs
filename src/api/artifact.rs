use crate::artifact::{
    self, AnsweredArtifact, Artifact, ArtifactResolution, ArtifactResolveSigning, ArtifactStore,
};
use crate::browser::{ArtifactDelivery, Outbound};
use crate::config::{IdpDescriptor, SpDescriptor};
use crate::model::{
    AuthnRequest, Received, RefusedAuthnRequest, SamlValidationContext, SsoResponse,
};
use crate::soap::SoapChannel;
use std::time::SystemTime;

use super::idp::{ResponseTransport, SsoResponseTo};
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
    /// protocol namespace, [`SamlError::ArtifactStoreUnavailable`] when
    /// `issued` cannot store the artifact, and another [`SamlError`] when
    /// metadata has no SOAP `ArtifactResolutionService` at `endpoint_index`,
    /// the artifact expiration overflows the supported time range, or the
    /// artifact value is already outstanding.
    pub fn issue_artifact(
        &self,
        service_provider: &SpDescriptor,
        protocol_xml: &str,
        endpoint_index: u16,
        issued: &mut (impl ArtifactStore + ?Sized),
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
    /// [`Outbound::headers`](crate::Outbound::headers). Pass `issued` (or
    /// another node's handle to the same shared [`ArtifactStore`]) to
    /// [`Self::answer_artifact_resolve`] when the service provider resolves
    /// the artifact.
    ///
    /// `outcome` says what the response reports, as for
    /// [`Self::respond_sso`]. An [`SsoOutcome::Failure`] is stored and
    /// delivered the same way, including the metadata default ACS fallback
    /// if the request's ACS index is no longer published.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the service provider publishes no
    /// HTTP-Artifact assertion consumer the request allows, this identity
    /// provider's metadata has no SOAP `ArtifactResolutionService` at the
    /// delivery's index, `issued` fails with
    /// [`SamlError::ArtifactStoreUnavailable`], or [`Self::respond_sso`] would
    /// fail, including [`SamlError::Invalid`] for an [`SsoOutcome::Failure`]
    /// with a top-level `Success` status. Returns
    /// [`SamlError::ProtocolProfile`] when [`RespondSso::relay_state`] is set
    /// and `request` carried `RelayState`.
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
        mut issued: &mut (impl ArtifactStore + ?Sized),
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, &mut issued);
        self.issue_sso(
            sp,
            SsoResponseTo::Request(request, &outcome.into()),
            options.delivered(transport),
        )
    }

    /// Store a signed, correlated `Requester` response and deliver its HTTP-Artifact.
    ///
    /// Pass the refusal from [`SamlError::AuthnRequestRefused`]. Send the
    /// returned browser action and use `issued` to answer the artifact
    /// resolution request, as for [`Self::respond_sso_artifact`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     ArtifactDelivery, IdentityProvider, IssuedArtifacts, RefusedAuthnRequest,
    ///     RespondSso, SamlError, SpDescriptor,
    /// };
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     refusal: &RefusedAuthnRequest,
    /// #     issued: &mut IssuedArtifacts,
    /// # ) -> Result<(), SamlError> {
    /// let response = idp.respond_sso_refusal_artifact(
    ///     sp, refusal, RespondSso::artifact(ArtifactDelivery::redirect(0)), issued,
    /// )?;
    /// let location = response.redirect_url()?;
    /// # let _ = location;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the delivery and signing errors of [`Self::respond_sso_refusal`].
    /// Also returns an error when the SOAP resolution endpoint is missing
    /// or the artifact cannot be stored.
    pub fn respond_sso_refusal_artifact(
        &self,
        sp: &SpDescriptor,
        refusal: &RefusedAuthnRequest,
        options: RespondSso<ArtifactDelivery>,
        mut issued: &mut (impl ArtifactStore + ?Sized),
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, &mut issued);
        self.issue_sso(
            sp,
            SsoResponseTo::Refusal(refusal),
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
        mut issued: &mut (impl ArtifactStore + ?Sized),
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, &mut issued);
        self.issue_sso(
            sp,
            SsoResponseTo::Unsolicited(&outcome.into()),
            options.delivered(transport),
        )
    }

    /// Answer `ArtifactResolve` with `ArtifactResponse`.
    ///
    /// The protocol message is included only when `presenter` is the service
    /// provider the artifact was issued to, `channel` supplies the protection
    /// that message requires, and `issued` atomically consumes the matching
    /// outstanding entry. [`AnsweredArtifact::release`] says whether the
    /// response includes the message. An unknown artifact, a different
    /// destination or presenter, insufficient channel protection, or a race
    /// lost to another responder gets `Success` without the message. An
    /// unsupported newer version gets `VersionMismatch`, with
    /// `RequestVersionTooHigh` for a newer major version. A present XML
    /// signature must cover the `ArtifactResolve` and verify against
    /// `presenter`'s signing keys before the request can be processed.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `request_envelope` cannot be read as a SOAP
    /// 1.1 envelope. Returns [`SamlError::ProtocolProfile`] when the body is
    /// not one `ArtifactResolve`, the request lacks exactly one `Artifact`
    /// value or has a second `Issuer`, or the required `ID`, `Version`, or UTC
    /// `IssueInstant` fails validation. A version below 2.0 also returns
    /// [`SamlError::ProtocolProfile`].
    /// Returns [`SamlError::ArtifactStoreUnavailable`] when `issued` fails
    /// during lookup, clock read, or atomic consume, without releasing an
    /// unconsumed message. An invalid signature returns a verification error
    /// and leaves the artifact outstanding. A present signature without a
    /// crypto provider returns [`SamlError::Unsupported`].
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
    ///     MetadataTrustPolicy::Unverified,
    /// )?;
    /// let idp_descriptor = IdpDescriptor::from_metadata_xml(
    ///     EntityId::try_new("https://idp.example.com/metadata")?,
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::Unverified,
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
        issued: &mut (impl ArtifactStore + ?Sized),
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
    /// Prepare an unsigned `ArtifactResolve` for the identity provider's `ArtifactResolutionService`.
    ///
    /// For an identity provider that requires a signed request, use
    /// [`Self::resolve_artifact_with_signed_request`].
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
    /// this resolution did not complete. [`ReplayPolicy::NoCache`](crate::ReplayPolicy::NoCache)
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
        validation: SamlValidationContext<'_>,
    ) -> Result<ArtifactResolution, SamlError> {
        self.prepare_artifact_resolution(
            identity_provider,
            artifact,
            channel,
            validation,
            ArtifactResolveSigning::Unsigned,
        )
    }

    /// Prepare an enveloped XML signature on the SOAP `ArtifactResolve` request.
    ///
    /// Use this when the identity provider requires a signed request. The
    /// service provider signs the protocol element with its configured signing
    /// credential and algorithm. The signature follows `Issuer` and uses the
    /// configured signature prefix, if present.
    ///
    /// The endpoint, channel protection, replay policy, and response handling
    /// follow [`Self::resolve_artifact`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resolve_artifact`]. Signing returns
    /// [`SamlError::Unsupported`] without a crypto provider,
    /// [`SamlError::MissingKey`] for a missing signing credential, or another
    /// [`SamlError`] if the credential cannot sign the request. A signing
    /// failure leaves the artifact available to retry in the requester cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     Artifact, ArtifactResolution, IdpDescriptor, SamlError, SamlValidationContext,
    ///     ServiceProvider, SoapChannel,
    /// };
    ///
    /// fn prepare_request(
    ///     sp: &ServiceProvider,
    ///     keycloak: &IdpDescriptor,
    ///     artifact: &Artifact,
    ///     channel: SoapChannel,
    ///     validation: SamlValidationContext<'_>,
    /// ) -> Result<ArtifactResolution, SamlError> {
    ///     sp.resolve_artifact_with_signed_request(keycloak, artifact, channel, validation)
    /// }
    /// ```
    pub fn resolve_artifact_with_signed_request(
        &self,
        identity_provider: &IdpDescriptor,
        artifact: &Artifact,
        channel: SoapChannel,
        validation: SamlValidationContext<'_>,
    ) -> Result<ArtifactResolution, SamlError> {
        self.prepare_artifact_resolution(
            identity_provider,
            artifact,
            channel,
            validation,
            ArtifactResolveSigning::Signed,
        )
    }

    fn prepare_artifact_resolution(
        &self,
        identity_provider: &IdpDescriptor,
        artifact: &Artifact,
        channel: SoapChannel,
        mut validation: SamlValidationContext<'_>,
        signing: ArtifactResolveSigning,
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
            signing,
        )
    }
}
