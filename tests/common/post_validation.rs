use saml_rs::{InMemoryReplayCache, ReplayPolicy, SamlValidationContext};
use std::time::SystemTime;

pub fn post_validation(cache: &mut InMemoryReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
}
