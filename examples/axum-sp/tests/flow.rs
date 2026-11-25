#![cfg(any(
    feature = "crypto-bergshamra",
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::{
    error::Error,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, Response, StatusCode},
    Router,
};
use axum_sp::{paths, Config, IdpLogoutTransport, PENDING_LIFETIME};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use saml_rs::{
    AcsEndpoint, AssertionId, AuthnRequest, AuthnRequestValidationPolicy, CertificatePem,
    Credentials, EntityId, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    InMemoryReplayCache, Inbound, LogoutSubject, MetadataTrustPolicy, NameId, NameIdFormat,
    PrivateKeyPem, Received, RelayState, ReplayCache, ReplayKey, ReplayPolicy, RespondSlo,
    RespondSso, SamlValidationContext, ServiceProvider, SessionIndex, SloEndpoint, SpConfig,
    SpDescriptor, SsoAssertion, SsoEndpoint, StartSlo, Status, X509Credential,
};
use tower::ServiceExt as _;
use url::{form_urlencoded, Url};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SP_BASE_URL: &str = "https://sp.example.test/";
const SP_ORIGIN: &str = "https://sp.example.test";
const SP_ENTITY_ID: &str = "https://sp.example.test/saml/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.test/metadata";
const NAME_ID: &str = "alice@example.com";
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
const IDP_ISSUANCE_LIFETIME: Duration = Duration::from_secs(60 * 60);

const SP_CERTIFICATE: &str = include_str!("../keys/sp-cert.pem");
const SP_PRIVATE_KEY: &str = include_str!("../keys/sp-key.pem");
const IDP_CERTIFICATE: &str = include_str!("../keys/keycloak-realm-cert.pem");
const IDP_PRIVATE_KEY: &str = include_str!("../keys/keycloak-realm-key.pem");

/// The application under test, with the identity provider it talks to and
/// the clock its handlers read.
struct Harness {
    router: Router,
    idp: IdentityProvider,
    sp_descriptor: SpDescriptor,
    start: SystemTime,
    clock_seconds: Arc<AtomicU64>,
    replay_cache: Arc<Mutex<InMemoryReplayCache>>,
}

/// A login the application started: what the browser carries to the IdP and back.
struct StartedLogin {
    pending_cookie: String,
    request: Received<AuthnRequest>,
}

impl Harness {
    async fn new() -> TestResult<Self> {
        let start_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let start = UNIX_EPOCH + Duration::from_secs(start_seconds);
        let clock_seconds = Arc::new(AtomicU64::new(start_seconds));
        let clock = {
            let clock_seconds = Arc::clone(&clock_seconds);
            move || UNIX_EPOCH + Duration::from_secs(clock_seconds.load(Ordering::SeqCst))
        };
        let replay_cache = Arc::new(Mutex::new(InMemoryReplayCache::with_clock(clock.clone())));

        let mut idp_validation = IdpValidationPolicy::default();
        idp_validation.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::redirect("https://idp.example.test/sso")?,
            )
            .slo_endpoint(SloEndpoint::redirect("https://idp.example.test/slo")?)
            .credentials(credentials(IDP_CERTIFICATE, IDP_PRIVATE_KEY))
            .issuance_lifetime(IDP_ISSUANCE_LIFETIME)
            .validation(idp_validation)
            .build()?,
        );
        let router = axum_sp::router(
            Config {
                public_base_url: Url::parse(SP_BASE_URL)?,
                idp_entity_id: IDP_ENTITY_ID.to_owned(),
                idp_metadata_xml: idp.metadata_xml().to_owned(),
                sp_signing_credential: X509Credential::new(
                    CertificatePem::new(SP_CERTIFICATE),
                    PrivateKeyPem::new(SP_PRIVATE_KEY),
                ),
                max_session_lifetime: MAX_SESSION_LIFETIME,
                idp_logout_transport: IdpLogoutTransport::HttpsOnly,
            },
            Arc::new(clock),
            Arc::clone(&replay_cache),
        )?;

        let metadata = router
            .clone()
            .oneshot(Request::get(paths::METADATA).body(Body::empty())?)
            .await?;
        assert_eq!(metadata.status(), StatusCode::OK);
        let sp_descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &body_text(metadata).await?,
            MetadataTrustPolicy::Unverified,
        )?;

        Ok(Self {
            router,
            idp,
            sp_descriptor,
            start,
            clock_seconds,
            replay_cache,
        })
    }

    fn set_clock(&self, elapsed: Duration) -> TestResult {
        let at = self.start + elapsed;
        self.clock_seconds
            .store(at.duration_since(UNIX_EPOCH)?.as_secs(), Ordering::SeqCst);
        Ok(())
    }

    async fn get(&self, path_and_query: &str, cookie: Option<&str>) -> TestResult<Response<Body>> {
        let mut request = Request::get(path_and_query);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        Ok(self
            .router
            .clone()
            .oneshot(request.body(Body::empty())?)
            .await?)
    }

    async fn post(
        &self,
        path: &str,
        fields: &[(String, String)],
        cookie: Option<&str>,
    ) -> TestResult<Response<Body>> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        Ok(self
            .router
            .clone()
            .oneshot(request.body(Body::from(body))?)
            .await?)
    }

    /// `POST /logout` from a page with `origin`, as the sign-out button posts it.
    async fn logout(
        &self,
        session_cookie: &str,
        origin: Option<&str>,
    ) -> TestResult<Response<Body>> {
        let mut request = Request::post(paths::LOGOUT).header(header::COOKIE, session_cookie);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        Ok(self
            .router
            .clone()
            .oneshot(request.body(Body::empty())?)
            .await?)
    }

    /// `GET /login`, then the identity provider receives the `AuthnRequest`.
    async fn start_login(&self, return_to: Option<&str>) -> TestResult<StartedLogin> {
        let path = match return_to {
            Some(return_to) => format!(
                "{}?{}",
                paths::LOGIN,
                form_urlencoded::Serializer::new(String::new())
                    .append_pair("return", return_to)
                    .finish()
            ),
            None => paths::LOGIN.to_owned(),
        };
        let response = self.get(&path, None).await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let pending_cookie = set_cookie(&response, "saml_pending").ok_or("no pending cookie")?;
        let location = Url::parse(location(&response)?)?;
        let request = self.idp.receive_sso(
            &self.sp_descriptor,
            Inbound::redirect(location.query().ok_or("no query")?),
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
        )?;
        Ok(StartedLogin {
            pending_cookie,
            request,
        })
    }

    /// The identity provider's HTTP-POST form answering `login`.
    fn respond(
        &self,
        login: &StartedLogin,
        assertion: SsoAssertion,
    ) -> TestResult<Vec<(String, String)>> {
        let response = self.idp.respond_sso(
            &self.sp_descriptor,
            &login.request,
            assertion,
            RespondSso::post(),
        )?;
        Ok(form_pairs(response.post_form()?.fields()))
    }

    /// A full login. Returns the session cookie.
    async fn sign_in(&self, assertion: SsoAssertion) -> TestResult<String> {
        let login = self.start_login(None).await?;
        let fields = self.respond(&login, assertion)?;
        let response = self
            .post(paths::ACS, &fields, Some(&login.pending_cookie))
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        Ok(set_cookie(&response, "sp_session").ok_or("no session cookie")?)
    }

    /// `GET /` with `session_cookie`: the page when signed in, `None` when
    /// redirected to login.
    async fn protected_page(&self, session_cookie: &str) -> TestResult<Option<String>> {
        let response = self.get("/", Some(session_cookie)).await?;
        match response.status() {
            StatusCode::OK => Ok(Some(body_text(response).await?)),
            StatusCode::SEE_OTHER => {
                assert_eq!(location(&response)?, paths::LOGIN);
                Ok(None)
            }
            other => Err(format!("GET / returned {other}").into()),
        }
    }
}

fn credentials(certificate: &str, private_key: &str) -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(certificate),
        PrivateKeyPem::new(private_key),
    ))
}

fn alice() -> SsoAssertion {
    SsoAssertion::new(NameId::new(NAME_ID).with_format(NameIdFormat::EmailAddress))
}

fn form_pairs(fields: &[saml_rs::FormField]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|field| (field.name().to_owned(), field.value().to_owned()))
        .collect()
}

fn field<'f>(fields: &'f [(String, String)], name: &str) -> TestResult<&'f str> {
    fields
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value.as_str()))
        .ok_or_else(|| format!("no {name} field").into())
}

fn with_field(fields: &[(String, String)], name: &str, value: String) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(key, old)| {
            if key == name {
                (key.clone(), value.clone())
            } else {
                (key.clone(), old.clone())
            }
        })
        .collect()
}

fn location(response: &Response<Body>) -> TestResult<&str> {
    Ok(response
        .headers()
        .get(header::LOCATION)
        .ok_or("no Location")?
        .to_str()?)
}

fn query_value(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

/// The `name=value` pair of a `Set-Cookie` that stores a non-empty value.
fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
    set_cookie_header(response, name).and_then(|cookie| cookie.split(';').next().map(str::to_owned))
}

/// The whole `Set-Cookie` header that stores a non-empty value under `name`.
fn set_cookie_header(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| {
            cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .is_some_and(|(key, value)| key == name && !value.is_empty())
        })
        .map(str::to_owned)
}

async fn body_text(response: Response<Body>) -> TestResult<String> {
    Ok(String::from_utf8(
        to_bytes(response.into_body(), usize::MAX).await?.to_vec(),
    )?)
}

fn decoded_response(fields: &[(String, String)]) -> TestResult<String> {
    Ok(String::from_utf8(
        STANDARD.decode(field(fields, "SAMLResponse")?)?,
    )?)
}

#[tokio::test]
async fn sp_initiated_login_reaches_the_protected_page() -> TestResult {
    let harness = Harness::new().await?;
    let unauthenticated = harness.get("/", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&unauthenticated)?, paths::LOGIN);

    let login = harness.get(paths::LOGIN, None).await?;
    let pending_cookie = set_cookie_header(&login, "saml_pending").ok_or("no pending cookie")?;
    let attributes: Vec<&str> = pending_cookie.split("; ").skip(1).collect();
    assert_eq!(
        attributes,
        [
            "HttpOnly",
            "Secure",
            "SameSite=None",
            "Path=/saml/acs",
            "Max-Age=600"
        ],
        "the IdP's cross-site POST to the ACS must carry the pending cookie"
    );

    let session_cookie = harness.sign_in(alice()).await?;

    let page = harness.get("/", Some(&session_cookie)).await?;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(
        page.headers()
            .get(header::CACHE_CONTROL)
            .map(|value| value.as_bytes()),
        Some(&b"no-store"[..])
    );
    let page = body_text(page).await?;
    assert!(page.contains(NAME_ID), "page: {page}");
    Ok(())
}

#[tokio::test]
async fn a_response_with_one_changed_byte_creates_no_session() -> TestResult {
    let harness = Harness::new().await?;
    let login = harness.start_login(None).await?;
    let fields = harness.respond(&login, alice())?;
    let xml = decoded_response(&fields)?;
    let tampered = xml.replacen(NAME_ID, "alicf@example.com", 1);
    assert_ne!(tampered, xml);
    let fields = with_field(&fields, "SAMLResponse", STANDARD.encode(tampered));

    let response = harness
        .post(paths::ACS, &fields, Some(&login.pending_cookie))
        .await?;

    assert!(response.status().is_client_error(), "{}", response.status());
    assert_eq!(set_cookie(&response, "sp_session"), None);
    Ok(())
}

#[tokio::test]
async fn pending_state_is_bound_to_the_browser_that_started_the_login() -> TestResult {
    let harness = Harness::new().await?;
    let login = harness.start_login(None).await?;
    let fields = harness.respond(&login, alice())?;

    let without_cookie = harness.post(paths::ACS, &fields, None).await?;
    assert!(
        without_cookie.status().is_client_error(),
        "{}",
        without_cookie.status()
    );
    assert_eq!(set_cookie(&without_cookie, "sp_session"), None);

    let other_browser = harness
        .post(paths::ACS, &fields, Some("saml_pending=another-browser"))
        .await?;
    assert!(
        other_browser.status().is_client_error(),
        "{}",
        other_browser.status()
    );
    assert_eq!(set_cookie(&other_browser, "sp_session"), None);

    let original_browser = harness
        .post(paths::ACS, &fields, Some(&login.pending_cookie))
        .await?;
    assert_eq!(original_browser.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie(&original_browser, "sp_session").is_some());
    Ok(())
}

#[tokio::test]
async fn pending_state_finishes_one_login() -> TestResult {
    let harness = Harness::new().await?;
    let login = harness.start_login(None).await?;
    let first = harness.respond(&login, alice())?;
    let finished = harness
        .post(paths::ACS, &first, Some(&login.pending_cookie))
        .await?;
    assert_eq!(finished.status(), StatusCode::SEE_OTHER);

    // A second response to the same request carries a new assertion ID, so
    // only the used-up pending entry can refuse it.
    let second = harness.respond(&login, alice())?;
    let again = harness
        .post(paths::ACS, &second, Some(&login.pending_cookie))
        .await?;

    assert!(again.status().is_client_error(), "{}", again.status());
    assert_eq!(set_cookie(&again, "sp_session"), None);
    Ok(())
}

#[tokio::test]
async fn the_shared_replay_cache_refuses_a_seen_assertion() -> TestResult {
    let harness = Harness::new().await?;
    let login = harness.start_login(None).await?;
    let fields = harness.respond(&login, alice())?;
    let xml = decoded_response(&fields)?;
    let document = roxmltree::Document::parse(&xml)?;
    let assertion_id = document
        .descendants()
        .find(|node| node.has_tag_name(("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")))
        .and_then(|assertion| assertion.attribute("ID"))
        .ok_or("no assertion ID")?;
    harness
        .replay_cache
        .lock()
        .map_err(|_| "replay cache lock poisoned")?
        .check_and_store(
            ReplayKey::Assertion(AssertionId::try_new(assertion_id)?),
            harness.start + IDP_ISSUANCE_LIFETIME,
        )?;

    let response = harness
        .post(paths::ACS, &fields, Some(&login.pending_cookie))
        .await?;

    assert!(response.status().is_client_error(), "{}", response.status());
    assert_eq!(set_cookie(&response, "sp_session"), None);
    Ok(())
}

#[tokio::test]
async fn a_pending_login_expires() -> TestResult {
    let harness = Harness::new().await?;
    let live = harness.start_login(None).await?;
    let expired = harness.start_login(None).await?;
    let live_fields = harness.respond(&live, alice())?;
    let expired_fields = harness.respond(&expired, alice())?;

    harness.set_clock(PENDING_LIFETIME - Duration::from_secs(1))?;
    let before_expiry = harness
        .post(paths::ACS, &live_fields, Some(&live.pending_cookie))
        .await?;
    assert_eq!(before_expiry.status(), StatusCode::SEE_OTHER);

    harness.set_clock(PENDING_LIFETIME)?;
    let at_expiry = harness
        .post(paths::ACS, &expired_fields, Some(&expired.pending_cookie))
        .await?;
    assert!(
        at_expiry.status().is_client_error(),
        "{}",
        at_expiry.status()
    );
    assert_eq!(set_cookie(&at_expiry, "sp_session"), None);
    Ok(())
}

#[tokio::test]
async fn an_unsolicited_response_creates_no_session() -> TestResult {
    let harness = Harness::new().await?;
    let response = harness.idp.initiate_sso(
        &harness.sp_descriptor,
        alice(),
        RespondSso::post().relay_state(RelayState::try_new("unsolicited")?),
    )?;
    let fields = form_pairs(response.post_form()?.fields());

    let posted = harness
        .post(paths::ACS, &fields, Some("saml_pending=unsolicited"))
        .await?;

    assert!(posted.status().is_client_error(), "{}", posted.status());
    assert_eq!(set_cookie(&posted, "sp_session"), None);
    Ok(())
}

#[tokio::test]
async fn login_returns_only_to_this_origin() -> TestResult {
    let harness = Harness::new().await?;
    let cases = [
        ("//evil.example", "https://sp.example.test/"),
        ("/\\evil.example", "https://sp.example.test/"),
        ("https://evil.example", "https://sp.example.test/"),
        (
            "/reports?year=2026",
            "https://sp.example.test/reports?year=2026",
        ),
    ];
    for (return_to, expected) in cases {
        let login = harness.start_login(Some(return_to)).await?;
        let fields = harness.respond(&login, alice())?;
        let response = harness
            .post(paths::ACS, &fields, Some(&login.pending_cookie))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "return={return_to}"
        );
        assert_eq!(location(&response)?, expected, "return={return_to}");
    }
    Ok(())
}

#[tokio::test]
async fn a_session_ends_at_the_earlier_of_its_deadlines() -> TestResult {
    let harness = Harness::new().await?;
    let one_hour = Duration::from_secs(60 * 60);
    let cases = [
        (None, MAX_SESSION_LIFETIME),
        (Some(MAX_SESSION_LIFETIME + one_hour), MAX_SESSION_LIFETIME),
        (Some(one_hour), one_hour),
    ];
    for (session_not_on_or_after, expected_lifetime) in cases {
        harness.set_clock(Duration::ZERO)?;
        let assertion = match session_not_on_or_after {
            Some(after) => alice().session_not_on_or_after(harness.start + after),
            None => alice(),
        };
        let session_cookie = harness.sign_in(assertion).await?;

        harness.set_clock(expected_lifetime - Duration::from_secs(1))?;
        assert!(
            harness.protected_page(&session_cookie).await?.is_some(),
            "SessionNotOnOrAfter {session_not_on_or_after:?}: ended early"
        );
        harness.set_clock(expected_lifetime)?;
        assert_eq!(
            harness.protected_page(&session_cookie).await?,
            None,
            "SessionNotOnOrAfter {session_not_on_or_after:?}: outlived its deadline"
        );
    }
    Ok(())
}

#[tokio::test]
async fn logout_ends_the_session_and_correlates_the_response() -> TestResult {
    let harness = Harness::new().await?;

    let session_cookie = harness.sign_in(alice()).await?;
    let logout = harness.logout(&session_cookie, Some(SP_ORIGIN)).await?;
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(harness.protected_page(&session_cookie).await?, None);
    let logout_request = Url::parse(location(&logout)?)?;
    let received = harness.idp.receive_slo(
        &harness.sp_descriptor,
        Inbound::redirect(logout_request.query().ok_or("no query")?),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
    )?;
    let logout_response = harness.idp.respond_slo(
        &harness.sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::redirect(),
    )?;
    let slo_path = format!(
        "{}?{}",
        paths::SLO,
        Url::parse(logout_response.redirect_url()?)?
            .query()
            .ok_or("no query")?
    );

    let completed = harness.get(&slo_path, None).await?;
    assert_eq!(completed.status(), StatusCode::OK);
    let unknown_relay_state = harness.get(&slo_path, None).await?;
    assert!(
        unknown_relay_state.status().is_client_error(),
        "{}",
        unknown_relay_state.status()
    );

    // A signed response for another logout request, sent with this logout's
    // live RelayState.
    let session_cookie = harness.sign_in(alice()).await?;
    let logout = harness.logout(&session_cookie, Some(SP_ORIGIN)).await?;
    let relay_state =
        query_value(&Url::parse(location(&logout)?)?, "RelayState").ok_or("no RelayState")?;
    let other_request = second_service_provider()?.start_slo(
        &IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            harness.idp.metadata_xml(),
            MetadataTrustPolicy::Unverified,
        )?,
        LogoutSubject::new(NameId::new(NAME_ID).with_format(NameIdFormat::EmailAddress))
            .with_session_index(SessionIndex::try_new("another-session")?),
        StartSlo::redirect().relay_state(RelayState::try_new(relay_state)?),
    )?;
    let received = harness.idp.receive_slo(
        &harness.sp_descriptor,
        Inbound::redirect(
            Url::parse(other_request.outbound.redirect_url()?)?
                .query()
                .ok_or("no query")?,
        ),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
    )?;
    let mismatched = harness.idp.respond_slo(
        &harness.sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::redirect(),
    )?;
    let mismatched_path = format!(
        "{}?{}",
        paths::SLO,
        Url::parse(mismatched.redirect_url()?)?
            .query()
            .ok_or("no query")?
    );

    let refused = harness.get(&mismatched_path, None).await?;
    assert!(refused.status().is_client_error(), "{}", refused.status());
    assert_eq!(harness.protected_page(&session_cookie).await?, None);
    Ok(())
}

#[tokio::test]
async fn logout_posted_from_another_origin_changes_nothing() -> TestResult {
    let harness = Harness::new().await?;
    let session_cookie = harness.sign_in(alice()).await?;

    for origin in [
        Some("https://evil.example"),
        Some("https://idp.example.test"),
        None,
    ] {
        let logout = harness.logout(&session_cookie, origin).await?;
        assert_eq!(logout.status(), StatusCode::FORBIDDEN, "Origin {origin:?}");
        assert!(
            logout.headers().get(header::SET_COOKIE).is_none(),
            "Origin {origin:?}"
        );
        assert!(
            harness.protected_page(&session_cookie).await?.is_some(),
            "Origin {origin:?} ended the session"
        );
    }
    Ok(())
}

/// Another service provider with the application's entity ID and keys, as an
/// earlier process of the same deployment would be.
fn second_service_provider() -> TestResult<ServiceProvider> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.test/saml/acs")?,
        )
        .slo_endpoint(SloEndpoint::redirect("https://sp.example.test/saml/slo")?)
        .credentials(credentials(SP_CERTIFICATE, SP_PRIVATE_KEY))
        .build()?,
    ))
}
