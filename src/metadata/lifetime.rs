//! `validUntil` and `cacheDuration` written on generated metadata.

use std::time::{Duration, SystemTime};

use crate::entity::format_saml_utc_date_time;
use crate::error::SamlError;
use crate::validator::offset_datetime_from_system_time;
use crate::xml::parse_generated_saml_utc_date_time;

/// Lifetime written on the root `EntityDescriptor` of generated metadata.
///
/// `validUntil` is when consumers must stop using the metadata.
/// `cacheDuration` is how long they should cache it before refreshing; a
/// consumer may keep using a copy older than that.
///
/// A `validUntil` instant is fixed when `Saml::sp` or `Saml::idp` builds the
/// metadata, so build a new `Saml` before it passes, or use
/// [`MetadataLifetime::CacheDuration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataLifetime {
    /// Write `validUntil`, truncated to whole seconds.
    ValidUntil(SystemTime),
    /// Write `cacheDuration`.
    CacheDuration(Duration),
    /// Write both `validUntil` and `cacheDuration`.
    ValidUntilAndCacheDuration {
        /// Instant written as `validUntil`, truncated to whole seconds.
        valid_until: SystemTime,
        /// Duration written as `cacheDuration`.
        cache_duration: Duration,
    },
}

pub(super) struct LifetimeAttributes {
    valid_until: Option<String>,
    cache_duration: Option<String>,
}

impl LifetimeAttributes {
    pub(super) fn new(lifetime: Option<MetadataLifetime>) -> Result<Self, SamlError> {
        let (valid_until, cache_duration) = match lifetime {
            None => (None, None),
            Some(MetadataLifetime::ValidUntil(valid_until)) => (Some(valid_until), None),
            Some(MetadataLifetime::CacheDuration(cache_duration)) => (None, Some(cache_duration)),
            Some(MetadataLifetime::ValidUntilAndCacheDuration {
                valid_until,
                cache_duration,
            }) => (Some(valid_until), Some(cache_duration)),
        };
        Ok(Self {
            valid_until: valid_until.map(valid_until_value).transpose()?,
            cache_duration: cache_duration.map(cache_duration_value),
        })
    }

    pub(super) fn attributes(&self) -> impl Iterator<Item = (&'static str, &str)> {
        let valid_until = self
            .valid_until
            .as_deref()
            .map(|value| ("validUntil", value));
        let cache_duration = self
            .cache_duration
            .as_deref()
            .map(|value| ("cacheDuration", value));
        valid_until.into_iter().chain(cache_duration)
    }
}

fn valid_until_value(valid_until: SystemTime) -> Result<String, SamlError> {
    let value = format_saml_utc_date_time(offset_datetime_from_system_time(valid_until)?);
    if parse_generated_saml_utc_date_time(&value).is_none() {
        return Err(SamlError::Invalid(
            "metadata validUntil must fall in the years 0001 through 9999".into(),
        ));
    }
    Ok(value)
}

fn cache_duration_value(cache_duration: Duration) -> String {
    match cache_duration.subsec_nanos() {
        0 => format!("PT{}S", cache_duration.as_secs()),
        nanos => format!("PT{}.{nanos:09}S", cache_duration.as_secs()),
    }
}
