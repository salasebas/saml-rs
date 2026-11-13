use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use saml_rs::{InMemoryReplayCache, ReplayCache, ReplayKey, SamlError};

/// Records successful writes to the built-in cache using a clock before the fixtures.
pub struct RecordingReplayCache {
    pub seen: HashMap<String, SystemTime>,
    cache: InMemoryReplayCache,
}

impl RecordingReplayCache {
    pub fn new(cache: InMemoryReplayCache) -> Self {
        Self {
            seen: HashMap::new(),
            cache,
        }
    }
}

impl Default for RecordingReplayCache {
    fn default() -> Self {
        Self::new(InMemoryReplayCache::with_clock(|| {
            SystemTime::UNIX_EPOCH - Duration::from_secs(86_400)
        }))
    }
}

impl ReplayCache for RecordingReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        self.cache.check_and_store(key, expires_at)?;
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}
