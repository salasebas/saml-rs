use std::{
    fmt::{Debug, Write as _},
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    extract::{RawQuery, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use saml_rs::{
    FormField, HttpHeader, Inbound, LogoutSubject, NameId, PendingAuthnRequest, RelayState,
    ReplayPolicy, SamlInstant, SamlValidationContext, StartSlo, StartSso,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::{info, warn};
use url::{form_urlencoded, Url};

use crate::{
    cookie, paths, return_url::same_origin_return_url, store::StoreUnavailable, AppState,
    IdpLogoutTransport, PENDING_LIFETIME,
};

type App = State<Arc<AppState>>;

pub(crate) struct PendingLogin {
    pending: PendingAuthnRequest,
    return_url: Url,
}

#[derive(Clone)]
pub(crate) struct Session {
    name_id: NameId,
    logout_subject: LogoutSubject,
}

pub(crate) async fn metadata(State(app): App) -> Response {
    (
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        app.sp.metadata_xml().to_owned(),
    )
        .into_response()
}

pub(crate) async fn login(State(app): App, RawQuery(query): RawQuery) -> Result<Response, Failure> {
    const OPERATION: &str = "start_sso";
    let requested = query
        .as_deref()
        .and_then(|query| query_value(query, "return"));
    let return_url = same_origin_return_url(&app.public_base_url, requested.as_deref());
    let relay_state = random_token(OPERATION)?;
    let options = StartSso::redirect().relay_state(
        RelayState::try_new(relay_state.as_str()).map_err(|error| internal(OPERATION, error))?,
    );
    let started = app
        .sp
        .start_sso(&app.idp, options)
        .map_err(|error| internal(OPERATION, error))?;
    let location = started
        .outbound
        .redirect_url()
        .map_err(|error| internal(OPERATION, error))?;
    let mut response = redirect(OPERATION, location)?;
    add_headers(OPERATION, &mut response, started.outbound.headers())?;
    append_cookie(
        OPERATION,
        &mut response,
        cookie::PENDING_LOGIN.set(&relay_state, PENDING_LIFETIME),
    )?;

    let now = app.now();
    info!(
        operation = OPERATION,
        request_id = started.pending.request_id().as_str(),
        outcome = "sent"
    );
    app.pending_logins.insert(
        relay_state,
        PendingLogin {
            pending: started.pending,
            return_url,
        },
        now + PENDING_LIFETIME,
        now,
    )?;
    Ok(response)
}

pub(crate) async fn acs(
    State(app): App,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Response, Failure> {
    const OPERATION: &str = "finish_sso";
    let relay_state = fields
        .iter()
        .find_map(|(name, value)| (name == "RelayState").then(|| value.clone()))
        .ok_or_else(|| bad_request(OPERATION, "the response has no RelayState"))?;
    if cookie::PENDING_LOGIN.read(&headers) != Some(relay_state.as_str()) {
        return Err(bad_request(
            OPERATION,
            "the pending-login cookie is missing or differs from RelayState",
        ));
    }
    let now = app.now();
    let PendingLogin {
        pending,
        return_url,
    } = app
        .pending_logins
        .take_live(&relay_state, now)?
        .ok_or_else(|| bad_request(OPERATION, "no live pending login has this RelayState"))?;
    let request_id = pending.request_id().as_str();

    let fields = fields
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect();
    let mut replay_cache = Arc::clone(&app.replay_cache);
    let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut replay_cache));
    let sso = app
        .sp
        .finish_sso(&app.idp, &pending, Inbound::post(fields), validation)
        .map_err(|error| refused(OPERATION, request_id, error))?;
    let (Some(name_id), Some(logout_subject)) = (sso.name_id(), sso.logout_subject()) else {
        return Err(refused(
            OPERATION,
            request_id,
            "the assertion has no NameID, which this application shows and logs out",
        ));
    };
    let deadline = session_deadline(now, app.max_session_lifetime, sso.session_not_on_or_after())
        .map_err(|error| refused(OPERATION, request_id, error))?;

    let session_lifetime = deadline
        .duration_since(now)
        .map_err(|_| refused(OPERATION, request_id, "SessionNotOnOrAfter has passed"))?;

    let session_id = random_token(OPERATION)?;
    let mut response = redirect(OPERATION, return_url.as_str())?;
    append_cookie(
        OPERATION,
        &mut response,
        cookie::SESSION.set(&session_id, session_lifetime),
    )?;
    append_cookie(OPERATION, &mut response, cookie::PENDING_LOGIN.clear())?;
    app.sessions.insert(
        session_id,
        Session {
            name_id: name_id.clone(),
            logout_subject,
        },
        deadline,
        now,
    )?;
    info!(
        operation = OPERATION,
        request_id,
        outcome = "signed_in",
        issuer = sso.issuer().as_str(),
        assertion_id = sso.assertion_id().as_str()
    );
    Ok(response)
}

pub(crate) async fn home(State(app): App, headers: HeaderMap) -> Result<Response, Failure> {
    let session = match cookie::SESSION.read(&headers) {
        Some(session_id) => app.sessions.get_live(session_id, app.now())?,
        None => None,
    };
    let Some(session) = session else {
        return redirect("home", paths::LOGIN);
    };
    Ok(Html(format!(
        "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n<title>Signed in</title>\n\
         <p>Signed in as <strong>{}</strong>.</p>\n\
         <form method=\"post\" action=\"{}\"><button>Sign out</button></form>\n",
        escape_html(session.name_id.value()),
        paths::LOGOUT
    ))
    .into_response())
}

pub(crate) async fn logout(State(app): App, headers: HeaderMap) -> Result<Response, Failure> {
    const OPERATION: &str = "start_slo";
    let now = app.now();
    let session = match cookie::SESSION.read(&headers) {
        Some(session_id) => app.sessions.take_live(session_id, now)?,
        None => None,
    };
    let Some(session) = session else {
        let mut response = redirect(OPERATION, "/")?;
        append_cookie(OPERATION, &mut response, cookie::SESSION.clear())?;
        return Ok(response);
    };

    let relay_state = random_token(OPERATION)?;
    let mut options = StartSlo::redirect().relay_state(
        RelayState::try_new(relay_state.as_str()).map_err(|error| internal(OPERATION, error))?,
    );
    match app.idp_logout_transport {
        IdpLogoutTransport::HttpsOnly => {}
        IdpLogoutTransport::AllowHttp => options = options.allow_http(),
    }
    let started = app
        .sp
        .start_slo(&app.idp, session.logout_subject, options)
        .map_err(|error| internal(OPERATION, error))?;
    let location = started
        .outbound
        .redirect_url()
        .map_err(|error| internal(OPERATION, error))?;
    let mut response = redirect(OPERATION, location)?;
    add_headers(OPERATION, &mut response, started.outbound.headers())?;
    append_cookie(OPERATION, &mut response, cookie::SESSION.clear())?;

    info!(
        operation = OPERATION,
        request_id = started.pending.request_id().as_str(),
        outcome = "sent"
    );
    app.pending_logouts
        .insert(relay_state, started.pending, now + PENDING_LIFETIME, now)?;
    Ok(response)
}

pub(crate) async fn slo(State(app): App, RawQuery(query): RawQuery) -> Result<Response, Failure> {
    const OPERATION: &str = "finish_slo";
    let query = query.ok_or_else(|| bad_request(OPERATION, "the request has no query"))?;
    let relay_state = query_value(&query, "RelayState")
        .ok_or_else(|| bad_request(OPERATION, "the response has no RelayState"))?;
    let now = app.now();
    let pending = app
        .pending_logouts
        .take_live(&relay_state, now)?
        .ok_or_else(|| bad_request(OPERATION, "no live pending logout has this RelayState"))?;
    let request_id = pending.request_id().as_str();

    app.sp
        .finish_slo(
            &app.idp,
            &pending,
            Inbound::redirect(query),
            SamlValidationContext::new(now, ReplayPolicy::NoCache),
        )
        .map_err(|error| refused(OPERATION, request_id, error))?;
    info!(operation = OPERATION, request_id, outcome = "signed_out");
    Ok(Html(
        "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n<title>Signed out</title>\n\
         <p>Signed out.</p>\n<p><a href=\"/\">Sign in again</a></p>\n",
    )
    .into_response())
}

/// A refused request. The handler that refuses it logs why.
#[derive(Debug)]
pub(crate) enum Failure {
    BadRequest,
    Refused,
    Internal,
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "Bad request.\n"),
            Self::Refused => (StatusCode::FORBIDDEN, "Sign-in refused.\n"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error.\n"),
        };
        (status, body).into_response()
    }
}

impl From<StoreUnavailable> for Failure {
    fn from(_: StoreUnavailable) -> Self {
        warn!(
            outcome = "error",
            error = "an in-memory store lock is poisoned"
        );
        Self::Internal
    }
}

fn bad_request(operation: &'static str, reason: &'static str) -> Failure {
    warn!(operation, outcome = "bad_request", reason);
    Failure::BadRequest
}

fn refused(operation: &'static str, request_id: &str, error: impl Debug) -> Failure {
    warn!(operation, request_id, outcome = "refused", ?error);
    Failure::Refused
}

fn internal(operation: &'static str, error: impl Debug) -> Failure {
    warn!(operation, outcome = "error", ?error);
    Failure::Internal
}

fn redirect(operation: &'static str, location: &str) -> Result<Response, Failure> {
    let location = HeaderValue::from_str(location).map_err(|error| internal(operation, error))?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

fn add_headers(
    operation: &'static str,
    response: &mut Response,
    headers: &[HttpHeader],
) -> Result<(), Failure> {
    for http_header in headers {
        let name = HeaderName::from_bytes(http_header.name().as_bytes())
            .map_err(|error| internal(operation, error))?;
        let value = HeaderValue::from_str(http_header.value())
            .map_err(|error| internal(operation, error))?;
        response.headers_mut().insert(name, value);
    }
    Ok(())
}

fn append_cookie<E: Debug>(
    operation: &'static str,
    response: &mut Response,
    cookie: Result<HeaderValue, E>,
) -> Result<(), Failure> {
    let cookie = cookie.map_err(|error| internal(operation, error))?;
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(())
}

/// The end of a new session: the configured maximum lifetime, or the
/// identity provider's `SessionNotOnOrAfter` when that is earlier.
fn session_deadline(
    now: SystemTime,
    max_session_lifetime: Duration,
    session_not_on_or_after: Option<&SamlInstant>,
) -> Result<SystemTime, String> {
    let lifetime_end = now
        .checked_add(max_session_lifetime)
        .ok_or("the maximum session lifetime overflows the clock")?;
    let Some(session_not_on_or_after) = session_not_on_or_after else {
        return Ok(lifetime_end);
    };
    let idp_end = OffsetDateTime::parse(session_not_on_or_after.as_str(), &Rfc3339)
        .map_err(|error| format!("SessionNotOnOrAfter is not an RFC 3339 instant: {error}"))?;
    Ok(lifetime_end.min(idp_end.into()))
}

fn query_value(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

/// 256 random bits, hex-encoded.
fn random_token(operation: &'static str) -> Result<String, Failure> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| internal(operation, error))?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}
