use std::{
    collections::{BTreeMap, HashSet},
    sync::Mutex,
    time::SystemTime,
};

use super::{ReplayCache, ReplayKey};
use crate::error::SamlError;

/// In-memory replay protection for a single process.
///
/// Each call drops expired entries before checking the key and the optional
/// entry limit. Live keys are never evicted. Entries expire at `expires_at`,
/// including equality. There is no background cleanup while the cache is idle.
///
/// Share one cache across all request handlers. State is lost on restart;
/// multiple processes or protection across restarts require shared durable
/// storage implementing [`ReplayCache`]. Use the same time source as your
/// [`super::SamlValidationContext`].
///
/// # Examples
///
/// A shared reference to the mutex implements [`ReplayCache`], locking only
/// during each check and store. A poisoned lock fails closed with
/// [`SamlError::Invalid`]; it does not reset the cache.
///
/// ```
/// use std::{sync::{Arc, Mutex}, time::SystemTime};
/// use saml_rs::{InMemoryReplayCache, ReplayPolicy, SamlValidationContext};
///
/// let cache = Arc::new(Mutex::new(
///     InMemoryReplayCache::new().with_max_entries(10_000),
/// ));
/// let mut shared_cache = cache.as_ref();
/// let validation = SamlValidationContext::new(
///     SystemTime::now(), ReplayPolicy::RequireCache(&mut shared_cache),
/// );
/// # let _ = validation;
/// ```
pub struct InMemoryReplayCache {
    entries: HashSet<ReplayKey>,
    expirations: BTreeMap<SystemTime, Vec<ReplayKey>>,
    max_entries: Option<usize>,
    clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl InMemoryReplayCache {
    /// Create an empty cache using [`SystemTime::now`] with no entry limit.
    pub fn new() -> Self {
        Self::with_clock(SystemTime::now)
    }

    /// Create an empty cache with a caller-controlled time source and no limit.
    ///
    /// The clock is read once per check. It must agree with the time source
    /// used for validation, or entries could expire before messages stop being
    /// accepted. A closure can read a shared test clock without sleeps.
    pub fn with_clock(clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        Self {
            entries: HashSet::new(),
            expirations: BTreeMap::new(),
            max_entries: None,
            clock: Box::new(clock),
        }
    }

    /// Limit the number of live entries. Zero refuses every new live key.
    ///
    /// A full cache returns [`SamlError::Invalid`] instead of evicting a live
    /// key. Duplicate keys still return [`SamlError::ReplayDetected`].
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = Some(max_entries);
        self
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache for InMemoryReplayCache {
    /// Reject a live duplicate, otherwise store the key until `expires_at`.
    ///
    /// A new key whose deadline has already passed is not stored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ReplayDetected`] for a live duplicate, even if the
    /// supplied deadline has passed. Returns [`SamlError::Invalid`] when the
    /// entry limit prevents storage. Neither error removes a live key or
    /// changes its deadline.
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let now = (self.clock)();
        while let Some(entry) = self.expirations.first_entry() {
            if *entry.key() > now {
                break;
            }
            for expired in entry.remove() {
                self.entries.remove(&expired);
            }
        }
        if self.entries.contains(&key) {
            return Err(SamlError::ReplayDetected {
                key: key.cache_key(),
            });
        }
        if expires_at <= now {
            return Ok(());
        }
        if self
            .max_entries
            .is_some_and(|limit| self.entries.len() >= limit)
        {
            return Err(SamlError::Invalid(
                "in-memory replay cache entry limit reached".into(),
            ));
        }
        self.entries.insert(key.clone());
        self.expirations.entry(expires_at).or_default().push(key);
        Ok(())
    }
}

impl ReplayCache for &Mutex<InMemoryReplayCache> {
    /// Check and store with the lock held only for this call.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] if the mutex is poisoned, or the cache's
    /// error if the key is a duplicate or its entry limit prevents storage.
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        self.lock()
            .map_err(|_| SamlError::Invalid("in-memory replay cache lock poisoned".into()))?
            .check_and_store(key, expires_at)
    }
}
