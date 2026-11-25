use std::time::Duration;

use axum::http::{header, header::InvalidHeaderValue, HeaderMap, HeaderValue};

use crate::paths;

/// Carries the RelayState of a started login to the assertion consumer.
///
/// The ACS request is a cross-site POST from the identity provider, and
/// browsers send only a `SameSite=None` cookie with it.
pub(crate) const PENDING_LOGIN: CookieSpec = CookieSpec {
    name: "saml_pending",
    path: paths::ACS,
    same_site: "None",
};

/// Carries the session ID.
pub(crate) const SESSION: CookieSpec = CookieSpec {
    name: "sp_session",
    path: "/",
    same_site: "Lax",
};

pub(crate) struct CookieSpec {
    name: &'static str,
    path: &'static str,
    same_site: &'static str,
}

impl CookieSpec {
    /// The value of this cookie in the request's `Cookie` headers.
    pub(crate) fn read<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find_map(|(name, value)| (name == self.name).then_some(value))
    }

    /// A `Set-Cookie` value that stores `value` for `max_age`.
    pub(crate) fn set(
        &self,
        value: &str,
        max_age: Duration,
    ) -> Result<HeaderValue, InvalidHeaderValue> {
        self.header(value, max_age.as_secs())
    }

    /// A `Set-Cookie` value that deletes this cookie.
    pub(crate) fn clear(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        self.header("", 0)
    }

    fn header(&self, value: &str, max_age_seconds: u64) -> Result<HeaderValue, InvalidHeaderValue> {
        let Self {
            name,
            path,
            same_site,
        } = self;
        let cookie = format!(
            "{name}={value}; HttpOnly; Secure; SameSite={same_site}; Path={path}; Max-Age={max_age_seconds}"
        );
        HeaderValue::from_str(&cookie)
    }
}
