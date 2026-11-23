use crate::browser::{ArtifactDelivery, LogoutBinding, SsoRequestBinding, SsoResponseBinding};
use crate::config::IdentifierEncryptionPolicy;
use crate::idp::ResponseMessageSignature;
use crate::model::{RelayState, RequestedAuthnContext};

pub use crate::model::{ForceAuthn, IsPassive};

/// Options for starting SP-initiated Web SSO.
///
/// A request for a transient identifier omits `AllowCreate`.
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
    ///
    /// The binding needs `SigAlg` and `Signature`. With
    /// [`AuthnRequestSigningPolicy::DoNotSign`](crate::AuthnRequestSigningPolicy::DoNotSign),
    /// [`ServiceProvider::start_sso`](crate::ServiceProvider::start_sso)
    /// returns [`SamlError::Invalid`](crate::SamlError::Invalid).
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
    /// [`ServiceProvider::finish_sso`](crate::ServiceProvider::finish_sso) requires the response
    /// to return it unchanged. A value longer than
    /// [`MAX_RELAY_STATE_BYTES`](crate::MAX_RELAY_STATE_BYTES) fails
    /// [`ServiceProvider::start_sso`](crate::ServiceProvider::start_sso).
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
    pub fn passive(mut self, passive: IsPassive) -> Self {
        self.passive = Some(passive);
        self
    }

    /// Set the requester's human-readable `ProviderName`. Omitted by default.
    ///
    /// The name may be empty and may contain any character XML 1.0 allows.
    /// [`ServiceProvider::start_sso`](crate::ServiceProvider::start_sso) returns
    /// [`SamlError::Invalid`](crate::SamlError::Invalid) for a name with a
    /// character XML 1.0 forbids.
    pub fn provider_name(mut self, provider_name: impl Into<String>) -> Self {
        self.provider_name = Some(provider_name.into());
        self
    }

    /// Request authentication contexts in preference order. Omitted by default.
    pub fn requested_authn_context(mut self, context: RequestedAuthnContext) -> Self {
        self.requested_authn_context = Some(context);
        self
    }

    /// Set the `AssertionConsumerServiceIndex` of the AuthnRequest.
    pub fn acs_index(mut self, acs_index: u16) -> Self {
        self.acs_index = Some(acs_index);
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
/// These options select delivery and response signing. The
/// [`SsoOutcome`](crate::SsoOutcome) passed with them says what it reports.
/// A successful response carries an authentication statement. An IdP that
/// advertises Single Logout includes the assertion ID as its session index.
/// `Delivery` is [`MessageDelivery`] when the browser carries the response,
/// and [`ArtifactDelivery`] when it carries an artifact for a stored one.
#[derive(Debug, Clone)]
pub struct RespondSso<Delivery = MessageDelivery> {
    pub(super) binding: SsoResponseBinding,
    pub(super) delivery: Delivery,
    pub(super) relay_state: Option<RelayState>,
    response_signing: ResponseSigning,
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
        }
    }
}

impl RespondSso<ArtifactDelivery> {
    /// Respond with HTTP-Artifact.
    ///
    /// [`IdentityProvider::respond_sso_artifact`](crate::IdentityProvider::respond_sso_artifact)
    /// and
    /// [`IdentityProvider::initiate_sso_artifact`](crate::IdentityProvider::initiate_sso_artifact)
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
    /// the Response so the ciphertext is integrity protected. Typed identity
    /// providers sign such Responses unless this is selected.
    pub fn allow_unsigned_encrypted_cbc(mut self) -> Self {
        self.response_signing = ResponseSigning::AllowUnsignedEncryptedCbc;
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

    pub(super) fn response_signature(
        &self,
        assertion_encrypted: bool,
        data_encryption_algorithm: &str,
    ) -> ResponseMessageSignature {
        let encrypted_cbc = assertion_encrypted
            && crate::constants::is_xml_encryption_cbc_algorithm(data_encryption_algorithm);
        match self.response_signing {
            ResponseSigning::Always => ResponseMessageSignature::Always,
            ResponseSigning::FollowEncryptedCbcRecommendation if encrypted_cbc => {
                ResponseMessageSignature::Always
            }
            ResponseSigning::FollowEncryptedCbcRecommendation
            | ResponseSigning::AllowUnsignedEncryptedCbc => {
                ResponseMessageSignature::UnlessAssertionsSigned
            }
        }
    }
}

/// HTTPS recommendation for a message the user agent carries to a peer
/// endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum PeerEndpointTransport {
    /// Send the user agent to an `https` peer endpoint.
    #[default]
    RequireHttps,
    /// Allow an `http` peer endpoint.
    AllowHttp,
}

/// Options for issuing a signed LogoutRequest. A service provider must
/// include at least one session index. A session authority includes an expiration.
#[derive(Debug, Clone)]
pub struct StartSlo {
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: Option<RelayState>,
    pub(super) identifier_encryption: IdentifierEncryptionPolicy,
    transport: PeerEndpointTransport,
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
    /// The request carries an XML signature. A service provider includes at
    /// least one `SessionIndex`.
    /// The request carries no RelayState, so a present
    /// [`Self::relay_state`] is rejected. The `https` check and
    /// [`Self::allow_http`] apply only to the browser bindings.
    ///
    /// POST [`Outbound::soap_request`](crate::Outbound::soap_request) with the
    /// deployment's HTTP client, then pass the SOAP response body to
    /// `finish_slo` as [`Inbound::soap`](crate::Inbound::soap).
    pub fn soap() -> Self {
        Self::new(LogoutBinding::Soap)
    }

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: None,
            identifier_encryption: IdentifierEncryptionPolicy::PlaintextIdentifiers,
            transport: PeerEndpointTransport::default(),
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

    /// Allow a session participant to deliver this LogoutRequest to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect the HTTP
    /// exchange with TLS. It does not remove `SessionIndex`, the request
    /// signature, or session-authority `NotOnOrAfter`.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn transport(&self) -> PeerEndpointTransport {
        self.transport
    }
}

/// Options for issuing a LogoutResponse.
///
/// The response carries the exact RelayState received with the
/// `LogoutRequest`.
#[derive(Debug, Clone)]
pub struct RespondSlo {
    pub(super) binding: LogoutBinding,
    transport: PeerEndpointTransport,
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
            transport: PeerEndpointTransport::default(),
        }
    }

    /// Allow a service provider to deliver this LogoutResponse to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect that HTTP
    /// exchange with TLS. The response remains signed.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn transport(&self) -> PeerEndpointTransport {
        self.transport
    }
}

/// Options for issuing a `<ManageNameIDRequest>`.
///
/// [`IdentityProvider::start_name_id_management`](crate::IdentityProvider::start_name_id_management)
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
    /// [`IdentityProvider::start_name_id_management`](crate::IdentityProvider::start_name_id_management)
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

    pub(super) fn transport(&self) -> PeerEndpointTransport {
        self.transport
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

    pub(super) fn transport(&self) -> PeerEndpointTransport {
        self.transport
    }
}

/// Options for answering a `<ManageNameIDRequest>` over HTTP-Redirect.
///
/// The response is always signed, carries the exact RelayState received with
/// the request, and goes to an `https` peer `ManageNameIDService` unless
/// [`Self::allow_http`] is selected.
#[derive(Debug, Clone, Default)]
pub struct RespondNameIdManagement {
    transport: PeerEndpointTransport,
}

impl RespondNameIdManagement {
    /// Answer at an `https` peer endpoint only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow delivery to an `http` `ManageNameIDService`.
    ///
    /// This relaxes the recommendation to protect the HTTP exchange with TLS.
    /// The response stays signed.
    pub fn allow_http(mut self) -> Self {
        self.transport = PeerEndpointTransport::AllowHttp;
        self
    }

    pub(super) fn transport(&self) -> PeerEndpointTransport {
        self.transport
    }
}
