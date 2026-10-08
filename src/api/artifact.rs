use crate::artifact::{self, Artifact, ArtifactDereference, ArtifactResolution, ArtifactUses};
use crate::browser::{ArtifactDelivery, Outbound};
use crate::config::{IdpDescriptor, SpDescriptor};
use crate::model::{AuthnRequest, Received, SsoResponse, Subject};
use crate::soap::SoapChannel;

use super::idp::ResponseTransport;
use super::raw_mapping::ensure_entity_id;
use super::{Idp, RespondSso, Saml, SamlError, Sp};
use crate::artifact::{AnsweredArtifact, IssuedArtifacts, IssuedMessage};

impl Saml<Idp> {
    /// Store `message` for `service_provider` and return the artifact that refers to it.
    ///
    /// `endpoint_index` selects this identity provider's SOAP
    /// `ArtifactResolutionService`. The caller keeps `issued` and passes it to
    /// [`Self::answer_artifact_resolve`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when metadata has no SOAP `ArtifactResolutionService`
    /// at `endpoint_index`, or when the artifact value is already outstanding.
    pub fn issue_artifact(
        &self,
        service_provider: &SpDescriptor,
        message: IssuedMessage,
        endpoint_index: u16,
        issued: &mut IssuedArtifacts,
    ) -> Result<Artifact, SamlError> {
        artifact::issue(
            &self.raw_identity_provider().metadata,
            service_provider,
            message,
            endpoint_index,
            issued,
        )
    }

    /// Respond to a received AuthnRequest with an HTTP-Artifact.
    ///
    /// The `<Response>` is stored in `issued` for `sp`, and the returned
    /// browser action carries its artifact and RelayState to the assertion
    /// consumer. Send that action with
    /// [`ArtifactDelivery::CACHE_CONTROL`](crate::ArtifactDelivery::CACHE_CONTROL)
    /// and [`ArtifactDelivery::PRAGMA`](crate::ArtifactDelivery::PRAGMA). Pass
    /// `issued` to [`Self::answer_artifact_resolve`] when the service provider
    /// resolves the artifact.
    ///
    /// A [`RespondSso::status`] other than success is stored and delivered
    /// the same way.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the service provider publishes no
    /// HTTP-Artifact assertion consumer the request allows, this identity
    /// provider's metadata has no SOAP `ArtifactResolutionService` at the
    /// delivery's index, or [`Self::respond_sso`] would fail.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     ArtifactDelivery, AuthnRequest, IssuedArtifacts, Received, RespondSso, Saml,
    ///     SpDescriptor, Subject,
    /// };
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<AuthnRequest>,
    /// #     subject: Subject,
    /// #     issued: &mut IssuedArtifacts,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.respond_sso_artifact(
    ///     sp,
    ///     request,
    ///     subject,
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
        subject: Subject,
        options: RespondSso<ArtifactDelivery>,
        issued: &mut IssuedArtifacts,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        let transport = ResponseTransport::Artifact(options.delivery, issued);
        self.issue_sso(sp, Some(request), subject, options.delivered(transport))
    }

    /// Initiate IdP-initiated SSO with an HTTP-Artifact.
    ///
    /// The artifact goes to the service provider's default HTTP-Artifact
    /// assertion consumer, or to its first one when none is default.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on [`Self::respond_sso_artifact`] and
    /// [`Self::initiate_sso`].
    pub fn initiate_sso_artifact(
        &self,
        sp: &SpDescriptor,
        subject: Subject,
        options: RespondSso<ArtifactDelivery>,
        issued: &mut IssuedArtifacts,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let transport = ResponseTransport::Artifact(options.delivery, issued);
        self.issue_sso(sp, None, subject, options.delivered(transport))
    }

    /// Answer `ArtifactResolve` with `ArtifactResponse`.
    ///
    /// The protocol message is included only when `presenter` is the service
    /// provider the artifact was issued to and `channel` supplies the protection
    /// that message requires. Any other understood request still gets an
    /// `ArtifactResponse`; [`AnsweredArtifact::release`] says whether the
    /// message was included. A request this method cannot read returns an error
    /// so the deployment can refuse it at HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `request_envelope` is not a SOAP 1.1
    /// `ArtifactResolve` with the required protocol attributes.
    ///
    /// # Examples
    ///
    /// The builders start on Recommended. This example selects
    /// [`IdpValidationPolicy::compatibility`](crate::IdpValidationPolicy::compatibility)
    /// and
    /// [`SpValidationPolicy::compatibility`](crate::SpValidationPolicy::compatibility)
    /// so `build` succeeds without the default crypto feature. Artifact
    /// resolution does not read those presets.
    ///
    /// ```
    /// use saml_rs::{
    ///     ArtifactDereference, ArtifactResolutionService, ArtifactUses, EndpointUrl,
    ///     EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy, IssuedArtifacts,
    ///     IssuedMessage, MetadataTrustPolicy, Saml, SoapChannel, SpConfig,
    ///     SpDescriptor, SpValidationPolicy, SsoEndpoint,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// let service = ArtifactResolutionService::new(
    ///     0,
    ///     EndpointUrl::try_new("https://idp.example.com/artifact")?,
    /// );
    /// let idp = Saml::idp(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    ///         .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///         .artifact_resolution_service(service)
    ///         .validation(IdpValidationPolicy::compatibility())
    ///         .build()?,
    /// )?;
    /// let sp = Saml::sp(
    ///     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    ///         .acs_endpoint(saml_rs::AcsEndpoint::post("https://sp.example.com/acs")?)
    ///         .validation(SpValidationPolicy::compatibility())
    ///         .build()?,
    /// )?;
    /// let sp_descriptor = SpDescriptor::from_metadata_xml(
    ///     sp.metadata_xml(),
    ///     MetadataTrustPolicy::UnsignedForCompatibility,
    /// )?;
    /// let idp_descriptor = IdpDescriptor::from_metadata_xml(
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::UnsignedForCompatibility,
    /// )?;
    /// let message = IssuedMessage::web_browser_sso_response(
    ///     r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">artifact-message</samlp:Response>"#,
    /// )?;
    /// let mut issued = IssuedArtifacts::new();
    /// let artifact = idp.issue_artifact(&sp_descriptor, message, 0, &mut issued)?;
    /// let channel = SoapChannel::mutually_authenticated_confidential();
    /// let resolution = sp.resolve_artifact(
    ///     &idp_descriptor,
    ///     &artifact,
    ///     ArtifactDereference::web_browser_sso(channel)?,
    ///     &mut ArtifactUses::enforce_single_use(),
    /// )?;
    /// let answer = idp.answer_artifact_resolve(
    ///     &sp_descriptor,
    ///     resolution.request().envelope(),
    ///     &mut issued,
    ///     channel,
    /// )?;
    /// let resolved = resolution.finish(answer.envelope())?;
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
        artifact::answer(
            &self.raw_identity_provider().metadata,
            presenter,
            request_envelope,
            issued,
            channel,
        )
    }
}

impl Saml<Sp> {
    /// Send `ArtifactResolve` to the identity provider's `ArtifactResolutionService`.
    ///
    /// The endpoint comes from the artifact's endpoint index in the identity
    /// provider metadata. Post [`ArtifactResolution::request`] with the
    /// deployment's HTTP client, then [`ArtifactResolution::finish`] with the
    /// SOAP response. TLS and HTTP authentication stay with that client;
    /// `dereference` records the protection it provided.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the artifact was not issued by `identity_provider`,
    /// metadata has no SOAP resolution service at the artifact's index, the
    /// channel lacks the protection `dereference` requires, or `uses` rejects
    /// a repeated artifact.
    pub fn resolve_artifact(
        &self,
        identity_provider: &IdpDescriptor,
        artifact: &Artifact,
        dereference: ArtifactDereference,
        uses: &mut ArtifactUses,
    ) -> Result<ArtifactResolution, SamlError> {
        let entity_id = self
            .raw_service_provider()
            .metadata
            .get_entity_id()
            .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?;
        artifact::resolve(entity_id, identity_provider, artifact, dereference, uses)
    }
}
