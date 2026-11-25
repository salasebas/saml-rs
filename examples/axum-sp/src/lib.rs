//! An Axum service provider that signs users in through SAML Web Browser SSO.
//!
//! [`router`] serves SP metadata, SP-initiated login, the assertion consumer
//! service, a protected page, and SP-initiated Single Logout. Pending
//! requests and sessions stay in server memory; cookies carry only random IDs.

mod cookie;
mod handlers;
mod return_url;
mod store;

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    routing::{get, post},
    Router,
};
use saml_rs::{
    AcsEndpoint, AuthnRequestSigningPolicy, CertificatePem, Credentials, EntityId, IdpDescriptor,
    InMemoryReplayCache, MetadataTrustPolicy, PendingLogoutRequest, PrivateKeyPem, SamlError,
    ServiceProvider, SloEndpoint, SpConfig, SpValidationPolicy, X509Credential,
};
use url::Url;

use crate::store::Store;

/// The time source of the request handlers.
///
/// Pending-request expiry, session deadlines, and SAML validation all read it.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// What the service provider needs to run.
#[derive(Debug, Clone)]
pub struct Config {
    /// The URL the browser uses to reach this service provider.
    ///
    /// The entity ID, the assertion consumer service, and the logout endpoint
    /// are paths below it.
    pub public_base_url: Url,
    /// The entity ID of the identity provider in [`Self::idp_metadata_xml`].
    pub idp_entity_id: String,
    /// The identity provider's SAML metadata.
    pub idp_metadata_xml: String,
    /// The PEM certificate published in SP metadata for its signing key.
    pub sp_certificate_pem: String,
    /// The PEM private key that signs `AuthnRequest` and `LogoutRequest`.
    pub sp_private_key_pem: String,
    /// The longest a session lasts, whatever `SessionNotOnOrAfter` says.
    pub max_session_lifetime: Duration,
    /// Whether logout may use an identity provider endpoint that is not `https`.
    pub idp_logout_transport: IdpLogoutTransport,
}

/// The transports a logout request to the identity provider may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpLogoutTransport {
    /// Send logout requests only to an `https` endpoint.
    HttpsOnly,
    /// Also send logout requests to an `http` endpoint, as a local Keycloak has.
    AllowHttp,
}

/// The SP's own URLs below [`Config::public_base_url`].
pub mod paths {
    /// SP metadata, and the SP entity ID.
    pub const METADATA: &str = "/saml/metadata";
    /// The HTTP-POST assertion consumer service.
    pub const ACS: &str = "/saml/acs";
    /// The HTTP-Redirect Single Logout endpoint.
    pub const SLO: &str = "/saml/slo";
    /// Starts SP-initiated login.
    pub const LOGIN: &str = "/login";
    /// Ends the local session and starts SP-initiated logout.
    pub const LOGOUT: &str = "/logout";
}

/// How long a started login or logout waits for the identity provider.
pub const PENDING_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Build the application.
///
/// `replay_cache` is the one cache every assertion consumer request checks.
/// Build it once at start-up with the same time source as `clock`.
///
/// # Errors
///
/// Returns [`SamlError`] when a URL, key, or the identity provider metadata
/// is invalid.
pub fn router(
    config: Config,
    clock: Clock,
    replay_cache: Arc<Mutex<InMemoryReplayCache>>,
) -> Result<Router, SamlError> {
    let state = AppState::new(config, clock, replay_cache)?;
    Ok(Router::new()
        .route(paths::METADATA, get(handlers::metadata))
        .route(paths::LOGIN, get(handlers::login))
        .route(paths::ACS, post(handlers::acs))
        .route("/", get(handlers::home))
        .route(paths::LOGOUT, post(handlers::logout))
        .route(paths::SLO, get(handlers::slo))
        .with_state(Arc::new(state)))
}

struct AppState {
    sp: ServiceProvider,
    idp: IdpDescriptor,
    public_base_url: Url,
    max_session_lifetime: Duration,
    idp_logout_transport: IdpLogoutTransport,
    clock: Clock,
    replay_cache: Arc<Mutex<InMemoryReplayCache>>,
    pending_logins: Store<handlers::PendingLogin>,
    pending_logouts: Store<PendingLogoutRequest>,
    sessions: Store<handlers::Session>,
}

impl AppState {
    fn new(
        config: Config,
        clock: Clock,
        replay_cache: Arc<Mutex<InMemoryReplayCache>>,
    ) -> Result<Self, SamlError> {
        let url = |path: &str| -> Result<String, SamlError> {
            config
                .public_base_url
                .join(path)
                .map(String::from)
                .map_err(|error| SamlError::Invalid(format!("public base URL: {error}")))
        };
        let mut validation = SpValidationPolicy::default();
        validation.authn_request_signing = AuthnRequestSigningPolicy::Sign;
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(url(paths::METADATA)?)?,
                AcsEndpoint::post(url(paths::ACS)?)?,
            )
            .slo_endpoint(SloEndpoint::redirect(url(paths::SLO)?)?)
            .credentials(
                Credentials::default().with_signing_credential(X509Credential::new(
                    CertificatePem::new(config.sp_certificate_pem),
                    PrivateKeyPem::new(config.sp_private_key_pem),
                )),
            )
            .validation(validation)
            .build()?,
        );
        let idp = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(config.idp_entity_id)?,
            &config.idp_metadata_xml,
            MetadataTrustPolicy::Unverified,
        )?;
        Ok(Self {
            sp,
            idp,
            public_base_url: config.public_base_url,
            max_session_lifetime: config.max_session_lifetime,
            idp_logout_transport: config.idp_logout_transport,
            clock,
            replay_cache,
            pending_logins: Store::default(),
            pending_logouts: Store::default(),
            sessions: Store::default(),
        })
    }

    fn now(&self) -> SystemTime {
        (self.clock)()
    }
}
