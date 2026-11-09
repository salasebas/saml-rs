use crate::browser::{LogoutBinding, SsoRequestBinding, SsoResponseBinding};
use crate::model::{Attributes, RelayStateParam, Status};
use crate::sp::WebBrowserSsoProducer;

pub use crate::model::{ForceAuthn, IsPassive};

/// Options for starting SP-initiated Web SSO.
#[derive(Debug, Clone)]
pub struct StartSso {
    pub(super) binding: SsoRequestBinding,
    pub(super) response_binding: Option<SsoResponseBinding>,
    pub(super) relay_state: RelayStateParam,
    pub(super) force_authn: Option<ForceAuthn>,
    pub(super) acs_index: Option<u16>,
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
            relay_state: RelayStateParam::absent(),
            force_authn: None,
            acs_index: None,
            web_browser_sso_producer: WebBrowserSsoProducer::Compatibility,
        }
    }

    /// Set the expected SAML Response binding.
    pub fn response_binding(mut self, binding: SsoResponseBinding) -> Self {
        self.response_binding = Some(binding);
        self
    }

    /// Set exact RelayState state for the outbound request.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set the exact `ForceAuthn` value.
    pub fn force_authn(mut self, force_authn: ForceAuthn) -> Self {
        self.force_authn = Some(force_authn);
        self
    }

    /// Select an AssertionConsumerServiceIndex.
    pub fn assertion_consumer_service_index(mut self, acs_index: u16) -> Self {
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
    pub fn apply_web_browser_sso_generation_rules(mut self) -> Self {
        self.web_browser_sso_producer = WebBrowserSsoProducer::Follow;
        self
    }
}

/// Options for issuing SAML Responses from an IdP.
#[derive(Debug, Clone)]
pub struct RespondSso {
    pub(super) binding: SsoResponseBinding,
    pub(super) relay_state: Option<RelayStateParam>,
    response_signing: ResponseSigning,
    pub(super) web_browser_sso_producer: WebBrowserSsoProducer,
    pub(super) status: Option<Status>,
    pub(super) attributes: Attributes,
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
            relay_state: None,
            response_signing: ResponseSigning::FollowEncryptedCbcRecommendation,
            web_browser_sso_producer: WebBrowserSsoProducer::Compatibility,
            status: None,
            attributes: Attributes::default(),
        }
    }

    /// Set the attributes of the assertion's `AttributeStatement`.
    ///
    /// Each attribute is written with its `Name`, its `NameFormat` when it has
    /// one, and one `xs:string` `AttributeValue` for each value. An attribute
    /// without values is written without `AttributeValue`. An empty collection
    /// writes no `AttributeStatement`, and so does an error response.
    ///
    /// The response is rejected when an [`crate::AttributeNameFormat::Basic`]
    /// name is not an XML name, or when a login response template is
    /// configured.
    pub fn attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the `Response` status. Omitting it emits top-level `Success` and
    /// its assertions.
    ///
    /// Any other top-level code omits assertions. A login response template
    /// cannot carry that response or a subordinate code.
    pub fn status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// Always authenticate the top-level SAML Response.
    ///
    /// HTTP-POST embeds an XML signature covering the Response. HTTP-POST-
    /// SimpleSign continues to use its binding-defined detached signature.
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
    /// [`Self::post`] and [`Self::simple_sign`] leave this off. When enabled, a
    /// successful response carries an authentication statement whose
    /// `AuthnInstant` is the assertion `IssueInstant` and whose
    /// `AuthnContextClassRef` is
    /// `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`. That class means
    /// the authentication mechanism was not recorded. It is not evidence of a
    /// particular authentication strength. When the identity provider metadata
    /// advertises `SingleLogoutService`, `SessionIndex` is the assertion `ID`.
    /// An unsolicited response omits `InResponseTo` on the response and on
    /// bearer subject confirmation data. CBC response signing is unchanged: it
    /// stays on unless
    /// [`Self::allow_unsigned_encrypted_cbc`] is selected.
    pub fn apply_web_browser_sso_generation_rules(mut self) -> Self {
        self.web_browser_sso_producer = WebBrowserSsoProducer::Follow;
        self
    }

    /// Set exact RelayState state for the response.
    ///
    /// When omitted for a response to a received request, the received
    /// RelayState is echoed. Pass [`RelayStateParam::absent`] to suppress echo.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
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
    DoNotSignForCompatibility,
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

/// HTTPS recommendation for a session participant's logout exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ParticipantLogoutTransport {
    /// Send the user agent to an `https` `SingleLogoutService`.
    #[default]
    RequireHttps,
    /// Allow an `http` `SingleLogoutService`.
    AllowHttp,
}

/// Producer-rule selection shared by logout requests and responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SingleLogoutRules {
    generation: SingleLogoutGeneration,
    transport: ParticipantLogoutTransport,
}

impl SingleLogoutRules {
    fn apply_generation_rules(mut self) -> Self {
        self.generation = SingleLogoutGeneration::Follow;
        self
    }

    fn allow_http(mut self) -> Self {
        self.transport = ParticipantLogoutTransport::AllowHttp;
        self
    }

    fn follows(self) -> bool {
        self.generation.follows()
    }

    fn allows_http(self) -> bool {
        matches!(self.transport, ParticipantLogoutTransport::AllowHttp)
    }
}

/// Options for issuing a LogoutRequest.
#[derive(Debug, Clone)]
pub struct StartSlo {
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: RelayStateParam,
    pub(super) signing: LogoutSigning,
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

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: RelayStateParam::absent(),
            signing: LogoutSigning::FollowLocalPolicy,
            rules: SingleLogoutRules::default(),
        }
    }

    /// Set exact RelayState state for the logout request.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set logout request signing behavior.
    pub fn signing(mut self, signing: LogoutSigning) -> Self {
        self.signing = signing;
        self
    }

    /// Apply Single Logout generation rules to this LogoutRequest.
    ///
    /// [`Self::redirect`], [`Self::post`], and [`Self::simple_sign`] leave this
    /// off, so existing generation is unchanged. When enabled, HTTP-Redirect,
    /// HTTP-POST, and HTTP-POST-SimpleSign requests are signed.
    /// [`LogoutSigning::DoNotSignForCompatibility`] is rejected.
    /// A service provider, acting as a session participant, includes at least
    /// one `SessionIndex` and sends the user agent to an `https`
    /// `SingleLogoutService` unless
    /// [`Self::allow_http_single_logout`] is selected.
    /// An identity provider, acting as a session authority, still emits
    /// `NotOnOrAfter` and may omit `SessionIndex`. The `https` recommendation
    /// is not applied to that role.
    pub fn apply_single_logout_generation_rules(mut self) -> Self {
        self.rules = self.rules.apply_generation_rules();
        self
    }

    /// Allow a session participant to deliver this LogoutRequest to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect the HTTP
    /// exchange with TLS. It does not remove `SessionIndex`, the request
    /// signature, or session-authority `NotOnOrAfter`.
    pub fn allow_http_single_logout(mut self) -> Self {
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
#[derive(Debug, Clone)]
pub struct RespondSlo {
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: Option<RelayStateParam>,
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

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: None,
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

    /// Set exact RelayState state for the logout response.
    ///
    /// When omitted, the received LogoutRequest RelayState is echoed. Pass
    /// [`RelayStateParam::absent`] to suppress echo.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Apply Single Logout generation rules to this LogoutResponse.
    ///
    /// [`Self::redirect`], [`Self::post`], and [`Self::simple_sign`] leave this
    /// off. Typed responses are already signed. When a service provider
    /// selects these rules, the response is delivered to an `https`
    /// `SingleLogoutService` unless
    /// [`Self::allow_http_single_logout`] is selected.
    /// An identity provider response does not gain that transport check.
    pub fn apply_single_logout_generation_rules(mut self) -> Self {
        self.rules = self.rules.apply_generation_rules();
        self
    }

    /// Allow a service provider to deliver this LogoutResponse to an `http`
    /// endpoint.
    ///
    /// This relaxes the Single Logout recommendation to protect that HTTP
    /// exchange with TLS. The response remains signed.
    pub fn allow_http_single_logout(mut self) -> Self {
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
