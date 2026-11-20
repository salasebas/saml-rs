use crate::browser::{ArtifactDelivery, LogoutBinding, SsoRequestBinding, SsoResponseBinding};
use crate::config::IdentifierEncryptionPolicy;
use crate::model::{RelayState, RequestedAuthnContext, Status};
use crate::sp::WebBrowserSsoProducer;

pub use crate::model::{ForceAuthn, IsPassive};

/// Options for starting SP-initiated Web SSO.
#[derive(Debug, Clone)]
pub struct StartSso {
    pub(super) binding: SsoRequestBinding,
    pub(super) response_binding: Option<SsoResponseBinding>,
    pub(super) relay_state: Option<RelayState>,
    pub(super) force_authn: Option<ForceAuthn>,
    pub(super) acs_index: Option<u16>,
    pub(super) passive: Option<IsPassive>,
    pub(super) provider_name: Option<String>,
    pub(super) requested_authn_context: Option<RequestedAuthnContext>,
    pub(super) web_browser_sso_producer: WebBrowserSsoProducer,
}

impl StartSso {
    /// Start SSO with HTTP-Redirect AuthnRequest dispatch.
    pub fn redirect() -> Self {
        Self::new(SsoRequestBinding::Redirect)
    }

    /// Start SSO with HTTP-POST AuthnRequest dispatch.
    pub fn post() -> Self {
        Self::new(SsoRequestBinding::Post)
    }

    /// Start SSO with HTTP-POST-SimpleSign AuthnRequest dispatch.
    pub fn simple_sign() -> Self {
        Self::new(SsoRequestBinding::SimpleSign)
    }

    fn new(binding: SsoRequestBinding) -> Self {
        Self {
            binding,
            response_binding: None,
            relay_state: None,
            force_authn: None,
            acs_index: None,
            passive: None,
            provider_name: None,
            requested_authn_context: None,
            web_browser_sso_producer: WebBrowserSsoProducer::Compatibility,
        }
    }

    /// Set the expected SAML Response binding.
    pub fn response_binding(mut self, binding: SsoResponseBinding) -> Self {
        self.response_binding = Some(binding);
        self
    }

    /// Set the RelayState the AuthnRequest carries. The request carries none
    /// by default.
    ///
    /// [`Saml<Sp>::finish_sso`](crate::Saml::finish_sso) requires the response
    /// to return it unchanged. A value longer than
    /// [`MAX_RELAY_STATE_BYTES`](crate::MAX_RELAY_STATE_BYTES) fails
    /// [`Saml<Sp>::start_sso`](crate::Saml::start_sso).
    pub fn relay_state(mut self, relay_state: RelayState) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Set the exact `ForceAuthn` value.
    pub fn force_authn(mut self, force_authn: ForceAuthn) -> Self {
        self.force_authn = Some(force_authn);
        self
    }

    /// Set `IsPassive`. When required, the IdP and user agent must not take
    /// visible control of the user interface. Omitted by default.
    ///
    /// Requires the built-in AuthnRequest renderer.
    pub fn passive(mut self, passive: IsPassive) -> Self {
        self.passive = Some(passive);
        self
    }

    /// Set the requester's human-readable `ProviderName`. Omitted by default.
    ///
    /// The name may be empty and may contain any character XML 1.0 allows.
    /// [`Saml<Sp>::start_sso`](crate::Saml::start_sso) returns
    /// [`SamlError::Invalid`](crate::SamlError::Invalid) for a name with a
    /// character XML 1.0 forbids. Requires the built-in AuthnRequest renderer.
    pub fn provider_name(mut self, provider_name: impl Into<String>) -> Self {
        self.provider_name = Some(provider_name.into());
        self
    }

    /// Request authentication contexts in preference order. Omitted by default.
    ///
    /// Requires the built-in AuthnRequest renderer.
    pub fn requested_authn_context(mut self, context: RequestedAuthnContext) -> Self {
        self.requested_authn_context = Some(context);
        self
    }

    /// Set the `AssertionConsumerServiceIndex` of the AuthnRequest.
    pub fn acs_index(mut self, acs_index: u16) -> Self {
        self.acs_index = Some(acs_index);
        self
    }

    /// Apply Web Browser SSO generation rules to this AuthnRequest.
    ///
    /// [`Self::redirect`], [`Self::post`], and [`Self::simple_sign`] leave this
    /// off, so existing generation is unchanged. When enabled, a transient
    /// `NameIDPolicy` omits `AllowCreate`. SAML Core forbids that attribute on
    /// a transient identifier request. Signing stays on
    /// [`crate::AuthnRequestSigningPolicy`] and is not turned on here.
    pub fn apply_producer_rules(mut self) -> Self {
        self.web_browser_sso_producer = WebBrowserSsoProducer::Follow;
        self
    }
}

/// Delivery of a `<Response>` the browser carries itself.
///
/// This is the delivery of [`RespondSso::post`] and
/// [`RespondSso::simple_sign`]. [`RespondSso::artifact`] uses
/// [`ArtifactDelivery`] in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageDelivery;

/// Options for issuing SAML Responses from an IdP.
///
/// These options say how the response is delivered and signed, and whether
/// the Web Browser SSO generation rules apply. The
/// [`SsoOutcome`](crate::SsoOutcome) passed with them says what it reports.
/// `Delivery` is [`MessageDelivery`] when the browser carries the response,
/// and [`ArtifactDelivery`] when it carries an artifact for a stored one.
#[derive(Debug, Clone)]
pub struct RespondSso<Delivery = MessageDelivery> {
    pub(super) binding: SsoResponseBinding,
    pub(super) delivery: Delivery,
    pub(super) relay_state: Option<RelayState>,
    response_signing: ResponseSigning,
    pub(super) web_browser_sso_producer: WebBrowserSsoProducer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseSigning {
    FollowEncryptedCbcRecommendation,
    Always,
    AllowUnsignedEncryptedCbc,
}

impl RespondSso {
    /// Respond with HTTP-POST.
    pub fn post() -> Self {
        Self::new(SsoResponseBinding::Post)
    }

    /// Respond with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(SsoResponseBinding::SimpleSign)
    }

    fn new(binding: SsoResponseBinding) -> Self {
        Self {
            binding,
            delivery: MessageDelivery,
            relay_state: None,
            response_signing: ResponseSigning::FollowEncryptedCbcRecommendation,
            web_browser_sso_producer: WebBrowserSsoProducer::Compatibility,
        }
    }
}

impl RespondSso<ArtifactDelivery> {
    /// Respond with HTTP-Artifact.
    ///
    /// [`Saml<Idp>::respond_sso_artifact`](crate::Saml::respond_sso_artifact)
    /// and
    /// [`Saml<Idp>::initiate_sso_artifact`](crate::Saml::initiate_sso_artifact)
    /// take these options. They store the response until the service
    /// provider resolves the artifact. The stored response is signed the way
    /// an HTTP-POST response is.
    pub fn artifact(delivery: ArtifactDelivery) -> Self {
        RespondSso::new(SsoResponseBinding::Artifact).delivered(delivery)
    }
}

impl<Delivery> RespondSso<Delivery> {
    /// The same options with another delivery.
    pub(super) fn delivered<Other>(self, delivery: Other) -> RespondSso<Other> {
        RespondSso {
            binding: self.binding,
            delivery,
            relay_state: self.relay_state,
            response_signing: self.response_signing,
            web_browser_sso_producer: self.web_browser_sso_producer,
        }
    }

    /// Always authenticate the top-level SAML Response.
    ///
    /// HTTP-POST embeds an XML signature covering the Response. HTTP-POST-
    /// SimpleSign continues to use its binding-defined detached signature.
    /// A response stored for an HTTP-Artifact embeds an XML signature, as
    /// HTTP-POST does.
    pub fn sign_response(mut self) -> Self {
        self.response_signing = ResponseSigning::Always;
        self
    }

    /// Allow an unsigned Response around a CBC-encrypted Assertion.
    ///
    /// This relaxes SAML V2.0 Approved Errata 05 E93, which recommends signing
    /// the Response so the ciphertext is integrity protected. It is not the
    /// legacy permissive preset. Typed identity providers sign such Responses
    /// unless this is selected.
    pub fn allow_unsigned_encrypted_cbc(mut self) -> Self {
        self.response_signing = ResponseSigning::AllowUnsignedEncryptedCbc;
        self
    }

    /// Apply Web Browser SSO generation rules to this response.
    ///
    /// [`RespondSso::post`], [`RespondSso::simple_sign`], and
    /// [`RespondSso::artifact`] leave this off. When enabled, a
    /// successful response carries an authentication statement whose
    /// `AuthnInstant` is
    /// [`SsoAssertion::with_authn_instant`](crate::SsoAssertion::with_authn_instant), or
    /// the assertion `IssueInstant` when it is omitted, and whose
    /// `AuthnContext` is
    /// [`SsoAssertion::with_authn_context`](crate::SsoAssertion::with_authn_context).
    /// Without it, the `AuthnContextClassRef` is
    /// `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`. That class means
    /// the authentication mechanism was not recorded. It is not evidence of a
    /// particular authentication strength. When the identity provider metadata
    /// advertises `SingleLogoutService`, `SessionIndex` is the assertion `ID`.
    /// An unsolicited response omits `InResponseTo` on the response and on
    /// bearer subject confirmation data. CBC response signing is unchanged: it
    /// stays on unless
    /// [`Self::allow_unsigned_encrypted_cbc`] is selected.
    pub fn apply_producer_rules(mut self) -> Self {
        self.web_browser_sso_producer = WebBrowserSsoProducer::Follow;
        self
    }

    /// Set the RelayState of a response whose request carried none, or of an
    /// unsolicited response.
    ///
    /// A response to an `AuthnRequest` that carried RelayState returns that
    /// value unchanged, up to
    /// [`MAX_RECEIVED_RELAY_STATE_BYTES`](crate::MAX_RECEIVED_RELAY_STATE_BYTES),
    /// and setting one here returns [`SamlError::ProtocolProfile`](crate::SamlError::ProtocolProfile).
    /// A value set here must not exceed
    /// [`MAX_RELAY_STATE_BYTES`](crate::MAX_RELAY_STATE_BYTES).
    pub fn relay_state(mut self, relay_state: RelayState) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    pub(super) fn should_sign_response(
        &self,
        assertion_encrypted: bool,
        data_encryption_algorithm: &str,
    ) -> bool {
        match self.response_signing {
            ResponseSigning::FollowEncryptedCbcRecommendation => {
                assertion_encrypted
                    && crate::constants::is_xml_encryption_cbc_algorithm(data_encryption_algorithm)
            }
            ResponseSigning::Always => true,
            ResponseSigning::AllowUnsignedEncryptedCbc => false,
        }
    }
}

/// Explicit signing choice for typed Single Logout requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutSigning {
    /// Use the local typed logout policy.
    FollowLocalPolicy,
    /// Sign this logout message.
    Sign,
    /// Send unsigned logout, preserving the samlify-port choice.
    DoNotSign,
}

/// Whether typed Single Logout generation follows producer rules.
///
/// [`Self::Compatibility`] is the samlify-port output kept for a caller
/// leaving the raw API. [`Self::Follow`] applies the producer obligations
/// recorded for this flow. It is not a validation preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SingleLogoutGeneration {
    /// Keep the samlify-port generation.
    #[default]
    Compatibility,
    /// Emit the producer obligations for this flow.
    Follow,
}

impl SingleLogoutGeneration {
    fn follows(self) -> bool {
        matches!(self, Self::Follow)
    }
}

/// HTTPS recommendation for a message the user agent carries to a peer
/// endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PeerEndpointTransport {
    /// Send the user agent to an `https` peer endpoint.
    #[default]
    RequireHttps,
    /// Allow an `http` peer endpoint.
    AllowHttp,
}

impl PeerEndpointTransport {
    fn allows_http(self) -> bool {
        matches!(self, Self::AllowHttp)
    }
}

/// Producer-rule selection shared by logout requests and responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SingleLogoutRules {
    generation: SingleLogoutGeneration,
    transport: PeerEndpointTransport,
}

impl SingleLogoutRules {
    fn apply_generation_rules(mut self) -> Self {
        self.generation = SingleLogoutGeneration::Follow;
        self
    }

    fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    fn follows(self) -> bool {
        self.generation.follows()
    }

    fn allows_http(self) -> bool {
        self.transport.allows_http()
    }
}

/// Options for issuing a LogoutRequest.
#[derive(Debug, Clone)]
pub struct StartSlo {
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: Option<RelayState>,
    pub(super) signing: LogoutSigning,
    pub(super) identifier_encryption: IdentifierEncryptionPolicy,
    rules: SingleLogoutRules,
}

impl StartSlo {
    /// Start SLO with HTTP-Redirect.
    pub fn redirect() -> Self {
        Self::new(LogoutBinding::Redirect)
    }

    /// Start SLO with HTTP-POST.
    pub fn post() -> Self {
        Self::new(LogoutBinding::Post)
    }

    /// Start SLO with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(LogoutBinding::SimpleSign)
    }

    /// Start SLO over SOAP.
    ///
    /// The Single Logout generation rules always apply: the request carries
    /// an XML signature, [`LogoutSigning::DoNotSign`] is
    /// rejected, and a service provider includes at least one `SessionIndex`.
    /// The request carries no RelayState, so a present
    /// [`Self::relay_state`] is rejected. The `https` check and
    /// [`Self::allow_http`] apply only to the browser bindings.
    ///
    /// POST [`Outbound::soap_request`](crate::Outbound::soap_request) with the
    /// deployment's HTTP client, then pass the SOAP response body to
    /// `finish_slo` as [`Inbound::soap`](crate::Inbound::soap).
    pub fn soap() -> Self {
        let mut options = Self::new(LogoutBinding::Soap);
        options.rules = options.rules.apply_generation_rules();
        options
    }

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: None,
            signing: LogoutSigning::FollowLocalPolicy,
            identifier_encryption: IdentifierEncryptionPolicy::PlaintextIdentifiers,
            rules: SingleLogoutRules::default(),
        }
    }

    /// Set the RelayState the LogoutRequest carries. The request carries none
    /// by default.
    ///
    /// `finish_slo` requires the response to return it unchanged. A value
    /// longer than [`MAX_RELAY_STATE_BYTES`](crate::MAX_RELAY_STATE_BYTES)
    /// fails `start_slo`.
    pub fn relay_state(mut self, relay_state: RelayState) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Set logout request signing behavior.
    pub fn signing(mut self, signing: LogoutSigning) -> Self {
        self.signing = signing;
        self
    }

    /// Set whether the subject `<NameID>` is sent as an `<EncryptedID>`.
    ///
    /// The default is [`IdentifierEncryptionPolicy::PlaintextIdentifiers`].
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`] encrypts the
    /// `<NameID>` for the first peer metadata `KeyDescriptor` with
    /// `use="encryption"`, with the configured data and key encryption
    /// algorithms, before the request is signed. A peer without that key
    /// returns [`crate::SamlError::MissingMetadata`].
    pub fn identifier_encryption(mut self, policy: IdentifierEncryptionPolicy) -> Self {
        self.identifier_encryption = policy;
        self
    }

    /// Apply Single Logout generation rules to this LogoutRequest.
    ///
    /// [`Self::redirect`], [`Self::post`], and [`Self::simple_sign`] leave this
    /// off, so existing generation is unchanged. When enabled, HTTP-Redirect,
    /// HTTP-POST, and HTTP-POST-SimpleSign requests are signed.
    /// [`LogoutSigning::DoNotSign`] is rejected.
    /// A service provider, acting as a session participant, includes at least
    /// one `SessionIndex` and sends the user agent to an `https`
    /// `SingleLogoutService` unless
    /// [`Self::allow_http`] is selected.
    /// An identity provider, acting as a session authority, still emits
    /// `NotOnOrAfter` and may omit `SessionIndex`. The `https` recommendation
    /// is not applied to that role.
    pub fn apply_producer_rules(mut self) -> Self {
        self.rules = self.rules.apply_generation_rules();
        self
    }

    /// Allow a session participant to deliver this LogoutRequest to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect the HTTP
    /// exchange with TLS. It does not remove `SessionIndex`, the request
    /// signature, or session-authority `NotOnOrAfter`.
    pub fn allow_http(mut self) -> Self {
        self.rules = self.rules.allow_http();
        self
    }

    pub(super) fn follows_generation_rules(&self) -> bool {
        self.rules.follows()
    }

    pub(super) fn allows_http(&self) -> bool {
        self.rules.allows_http()
    }
}

/// Options for issuing a LogoutResponse.
///
/// The response carries the exact RelayState received with the
/// `LogoutRequest`.
#[derive(Debug, Clone)]
pub struct RespondSlo {
    pub(super) binding: LogoutBinding,
    pub(super) status: Option<Status>,
    rules: SingleLogoutRules,
}

impl RespondSlo {
    /// Respond with HTTP-Redirect.
    pub fn redirect() -> Self {
        Self::new(LogoutBinding::Redirect)
    }

    /// Respond with HTTP-POST.
    pub fn post() -> Self {
        Self::new(LogoutBinding::Post)
    }

    /// Respond with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(LogoutBinding::SimpleSign)
    }

    /// Respond over SOAP to a request received as
    /// [`Inbound::soap`](crate::Inbound::soap).
    ///
    /// The response is signed and carries no `Destination` and no RelayState.
    /// A request received with RelayState cannot be answered over SOAP.
    /// Return [`Outbound::soap_response`](crate::Outbound::soap_response) as the
    /// HTTP 200 body of that SOAP request.
    pub fn soap() -> Self {
        Self::new(LogoutBinding::Soap)
    }

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            status: None,
            rules: SingleLogoutRules::default(),
        }
    }

    /// Set the `LogoutResponse` status. Omitting it emits top-level `Success`.
    ///
    /// A logout-response template carries only the top-level code. A
    /// subordinate code is rejected when a template is set.
    pub fn status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// Apply Single Logout generation rules to this LogoutResponse.
    ///
    /// [`Self::redirect`], [`Self::post`], and [`Self::simple_sign`] leave this
    /// off. Typed responses are already signed. When a service provider
    /// selects these rules, the response is delivered to an `https`
    /// `SingleLogoutService` unless
    /// [`Self::allow_http`] is selected.
    /// An identity provider response does not gain that transport check.
    pub fn apply_producer_rules(mut self) -> Self {
        self.rules = self.rules.apply_generation_rules();
        self
    }

    /// Allow a service provider to deliver this LogoutResponse to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect that HTTP
    /// exchange with TLS. The response remains signed.
    pub fn allow_http(mut self) -> Self {
        self.rules = self.rules.allow_http();
        self
    }

    pub(super) fn follows_generation_rules(&self) -> bool {
        self.rules.follows()
    }

    pub(super) fn allows_http(&self) -> bool {
        self.rules.allows_http()
    }
}

/// Options for issuing a `<ManageNameIDRequest>`.
///
/// [`Saml<Idp>::start_name_id_management`](crate::Saml::start_name_id_management)
/// sends the request over SOAP, and `start_name_id_management_redirect` sends
/// it over HTTP-Redirect. Over HTTP-Redirect the request is always signed and
/// goes to an `https` peer `ManageNameIDService` unless [`Self::allow_http`]
/// is selected.
#[derive(Debug, Clone, Default)]
pub struct StartNameIdManagement {
    pub(super) relay_state: Option<RelayState>,
    pub(super) identifier_encryption: IdentifierEncryptionPolicy,
    transport: PeerEndpointTransport,
}

impl StartNameIdManagement {
    /// Start with no RelayState, plaintext identifiers, and an `https` peer
    /// endpoint.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the RelayState the ManageNameIDRequest carries. The request
    /// carries none by default.
    ///
    /// The response must return it unchanged. A value longer than
    /// [`MAX_RELAY_STATE_BYTES`](crate::MAX_RELAY_STATE_BYTES) fails the start
    /// operation. A SOAP request carries no RelayState:
    /// [`Saml<Idp>::start_name_id_management`](crate::Saml::start_name_id_management)
    /// returns [`SamlError::ProtocolProfile`](crate::SamlError::ProtocolProfile)
    /// when one is set.
    pub fn relay_state(mut self, relay_state: RelayState) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Set whether the `<NameID>` and `<NewID>` are sent as `<EncryptedID>`
    /// and `<NewEncryptedID>`.
    ///
    /// The default is [`IdentifierEncryptionPolicy::PlaintextIdentifiers`].
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`] encrypts both for
    /// the first encryption certificate in the peer's metadata, with the
    /// configured data and key encryption algorithms. Over HTTP-Redirect
    /// that happens before the request is signed. A peer without that
    /// certificate returns [`crate::SamlError::MissingMetadata`].
    pub fn identifier_encryption(mut self, policy: IdentifierEncryptionPolicy) -> Self {
        self.identifier_encryption = policy;
        self
    }

    /// Allow delivery over HTTP-Redirect to an `http` `ManageNameIDService`.
    ///
    /// This relaxes the recommendation to protect the HTTP exchange with TLS.
    /// The request stays signed. It has no effect over SOAP, where the
    /// deployment sends the request itself.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn allows_http(&self) -> bool {
        self.transport.allows_http()
    }
}

/// Options for reading a `<ManageNameIDRequest>` over HTTP-Redirect.
///
/// A request that the provider answers without processing it, see
/// [`crate::NameIdManagementRefusal`], gets a signed response to an `https`
/// peer `ManageNameIDService` unless [`Self::allow_http`] is selected.
#[derive(Debug, Clone, Default)]
pub struct ReceiveNameIdManagement {
    transport: PeerEndpointTransport,
}

impl ReceiveNameIdManagement {
    /// Answer a refused request at an `https` peer endpoint only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow the response to a refused request to go to an `http`
    /// `ManageNameIDService`.
    ///
    /// This relaxes the recommendation to protect the HTTP exchange with TLS.
    /// The response stays signed.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn allows_http(&self) -> bool {
        self.transport.allows_http()
    }
}

/// Options for answering a `<ManageNameIDRequest>`.
///
/// [`Saml<Idp>::respond_name_id_management`](crate::Saml::respond_name_id_management)
/// answers over SOAP, and `respond_name_id_management_redirect` answers over
/// HTTP-Redirect. Over HTTP-Redirect the response is always signed, carries
/// the exact RelayState received with the request, and goes to an `https`
/// peer `ManageNameIDService` unless [`Self::allow_http`] is selected.
#[derive(Debug, Clone, Default)]
pub struct RespondNameIdManagement {
    pub(super) status: Option<Status>,
    transport: PeerEndpointTransport,
}

impl RespondNameIdManagement {
    /// Start with a `Success` status and an `https` peer endpoint.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the response status. Omitting it emits top-level `Success`.
    ///
    /// For a `<NameID>` this provider does not recognize, pass an error
    /// status, optionally with
    /// [`crate::SubordinateStatusCode::unknown_principal`].
    pub fn status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// Allow delivery over HTTP-Redirect to an `http` `ManageNameIDService`.
    ///
    /// This relaxes the recommendation to protect the HTTP exchange with TLS.
    /// The response stays signed. It has no effect over SOAP, where the
    /// response is the body of the HTTP response to the request.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn allows_http(&self) -> bool {
        self.transport.allows_http()
    }
}
