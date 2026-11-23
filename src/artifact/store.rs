use std::cell::RefMut;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime};

use crate::config::EntityId;
use crate::error::SamlError;

use super::Artifact;

/// SOAP channel protection required to resolve an issued artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArtifactChannelRequirement {
    /// Mutual authentication and integrity protection.
    Authenticated,
    /// Mutual authentication, integrity protection, and confidentiality.
    Confidential,
}

/// Protocol message and release requirements stored for one issued artifact.
///
/// A shared [`ArtifactStore`] persists this value outside the issuing process.
/// Because the stored XML is usually a `<Response>` carrying an assertion,
/// protect it with the same confidentiality, integrity, and access controls
/// your deployment gives to sessions.
///
/// `Debug` omits the protocol message XML.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedArtifact {
    service_provider: EntityId,
    message_xml: String,
    required_channel: ArtifactChannelRequirement,
    expires_at: SystemTime,
}

impl fmt::Debug for IssuedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedArtifact")
            .field("service_provider", &self.service_provider)
            .field("required_channel", &self.required_channel)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl IssuedArtifact {
    /// Build an issued artifact record loaded from an external store.
    pub fn new(
        service_provider: EntityId,
        message_xml: impl Into<String>,
        required_channel: ArtifactChannelRequirement,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            service_provider,
            message_xml: message_xml.into(),
            required_channel,
            expires_at,
        }
    }

    /// Entity ID of the service provider allowed to resolve this artifact.
    pub fn service_provider(&self) -> &EntityId {
        &self.service_provider
    }

    /// Standalone XML of the stored SAML protocol element.
    pub fn message_xml(&self) -> &str {
        &self.message_xml
    }

    /// SOAP channel protection required before releasing the message.
    pub fn required_channel(&self) -> ArtifactChannelRequirement {
        self.required_channel
    }

    /// Wall-clock time at which this artifact stops being resolvable.
    ///
    /// An artifact expires at `expires_at`, including equality.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// Caller-owned store for artifacts issued by an identity provider.
///
/// Use [`IssuedArtifacts`] for a single process. Multiple nodes behind one
/// `ArtifactResolutionService` endpoint require a shared store implementing
/// this trait so any node can answer `ArtifactResolve` for an artifact issued
/// by another node.
///
/// Stored entries usually carry a Web Browser SSO `<Response>` with its
/// assertion. Protect a shared store with the same confidentiality, integrity,
/// and access controls your deployment gives to sessions.
///
/// Implementations must leave an artifact outstanding during [`Self::lookup`]
/// and remove it atomically in [`Self::consume`], returning `Ok(true)` to at
/// most one concurrent caller.
///
/// # Examples
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
/// use saml_rs::{ArtifactStore, IssuedArtifacts};
///
/// let shared = Arc::new(Mutex::new(IssuedArtifacts::expire_after(
///     Duration::from_secs(60),
/// )));
/// let mut node_a = Arc::clone(&shared);
/// let mut node_b = Arc::clone(&shared);
/// fn accepts_store(_: &mut dyn ArtifactStore) {}
/// accepts_store(&mut node_a);
/// accepts_store(&mut node_b);
/// ```
pub trait ArtifactStore {
    /// How long each newly issued artifact remains resolvable.
    ///
    /// Choose the shortest duration in which service providers can receive the
    /// artifact and send `ArtifactResolve`. A zero duration resolves nothing.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::ArtifactStoreUnavailable`] if the store cannot read
    /// its configuration.
    fn lifetime(&self) -> Result<Duration, SamlError>;

    /// Current wall-clock time used for artifact expiry.
    ///
    /// Defaults to [`SystemTime::now`]. Override this in tests to advance time
    /// without sleeping, or when the store reads a synchronized clock.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::ArtifactStoreUnavailable`] if the store cannot read
    /// its clock.
    fn now(&self) -> Result<SystemTime, SamlError> {
        Ok(SystemTime::now())
    }

    /// Store `entry` under `artifact` when `artifact` is not already
    /// outstanding.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::Invalid`] if an unexpired entry for `artifact` is
    /// already present. Return [`SamlError::ArtifactStoreUnavailable`] if the
    /// store cannot persist the entry.
    fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError>;

    /// Look up an outstanding entry for `artifact` without consuming it.
    ///
    /// Return `Ok(None)` when `artifact` is absent or expired. This lookup
    /// must leave the artifact outstanding so a withheld request does not
    /// prevent the intended service provider from resolving it.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::ArtifactStoreUnavailable`] if the store cannot read
    /// the entry.
    fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError>;

    /// Atomically remove `artifact` only if the currently outstanding entry is
    /// still unexpired and equals `expected`.
    ///
    /// Return `Ok(true)` only when this call removed the matching outstanding
    /// entry. Return `Ok(false)` when `artifact` is absent, expired, already
    /// consumed by another caller, or no longer matches `expected`.
    ///
    /// At most one concurrent caller may observe `Ok(true)` for a given
    /// artifact.
    ///
    /// # Errors
    ///
    /// Return [`SamlError::ArtifactStoreUnavailable`] if the store cannot
    /// complete the atomic consume. The identity provider never releases the
    /// message when this method returns an error.
    fn consume(
        &mut self,
        artifact: &Artifact,
        expected: &IssuedArtifact,
    ) -> Result<bool, SamlError>;
}

macro_rules! forward_artifact_store {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl<T: ArtifactStore + ?Sized> ArtifactStore for $ty {
                fn lifetime(&self) -> Result<Duration, SamlError> {
                    (**self).lifetime()
                }

                fn now(&self) -> Result<SystemTime, SamlError> {
                    (**self).now()
                }

                fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
                    (**self).store(artifact, entry)
                }

                fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
                    (**self).lookup(artifact)
                }

                fn consume(
                    &mut self,
                    artifact: &Artifact,
                    expected: &IssuedArtifact,
                ) -> Result<bool, SamlError> {
                    (**self).consume(artifact, expected)
                }
            }
        )+
    };
}

forward_artifact_store!(
    &mut T,
    Box<T>,
    MutexGuard<'_, T>,
    RwLockWriteGuard<'_, T>,
    RefMut<'_, T>,
);

type StoreClock = Box<dyn Fn() -> SystemTime + Send + Sync + UnwindSafe + RefUnwindSafe>;

/// In-memory store of artifacts an identity provider has issued and not yet
/// resolved.
///
/// An artifact resolves only before its wall-clock expiration. Each operation
/// drops expired entries, so memory holds only unexpired artifacts.
///
/// State stays in one process and is lost on restart. Multiple nodes behind
/// one `ArtifactResolutionService` require a shared [`ArtifactStore`].
///
/// `Debug` reports the configured lifetime and stored entry count without
/// artifacts or message XML, and does not read the clock.
///
/// # Examples
///
/// An `Arc<Mutex<IssuedArtifacts>>` implements [`ArtifactStore`], locking only
/// during each store call. A poisoned lock fails closed with
/// [`SamlError::ArtifactStoreUnavailable`].
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
/// use saml_rs::IssuedArtifacts;
///
/// let shared = Arc::new(Mutex::new(IssuedArtifacts::expire_after(
///     Duration::from_secs(60),
/// )));
/// # let _ = shared;
/// ```
pub struct IssuedArtifacts {
    lifetime: Duration,
    entries: HashMap<String, IssuedArtifact>,
    expirations: BTreeMap<SystemTime, Vec<String>>,
    clock: StoreClock,
}

impl fmt::Debug for IssuedArtifacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedArtifacts")
            .field("lifetime", &self.lifetime)
            .field("stored_entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl IssuedArtifacts {
    /// Outstanding artifacts that each resolve for `lifetime` after issue.
    ///
    /// Choose the shortest `lifetime` in which the service provider receives
    /// the artifact and sends `ArtifactResolve`. A later `ArtifactResolve`
    /// gets Success without the message. The replay retention the service
    /// provider passes to [`ServiceProvider::resolve_artifact`](crate::ServiceProvider::resolve_artifact)
    /// should be longer. A zero `lifetime` resolves nothing.
    pub fn expire_after(lifetime: Duration) -> Self {
        Self {
            lifetime,
            entries: HashMap::new(),
            expirations: BTreeMap::new(),
            clock: Box::new(SystemTime::now),
        }
    }

    /// Replace the wall-clock time source used for artifact expiry.
    ///
    /// A closure can read a shared test clock without sleeps.
    pub fn with_clock(
        mut self,
        clock: impl Fn() -> SystemTime + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    ) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Discard `artifact` and its stored message without returning it.
    ///
    /// Returns whether the artifact was outstanding. A later `ArtifactResolve`
    /// for it gets Success without the message.
    pub fn remove(&mut self, artifact: &Artifact) -> bool {
        let now = (self.clock)();
        self.purge_expired(now);
        self.entries
            .remove(artifact.as_str())
            .is_some_and(|entry| entry.expires_at() > now)
    }

    fn purge_expired(&mut self, now: SystemTime) {
        while let Some(bucket) = self.expirations.first_entry() {
            if *bucket.key() > now {
                break;
            }
            for key in bucket.remove() {
                if self
                    .entries
                    .get(&key)
                    .is_some_and(|entry| entry.expires_at() <= now)
                {
                    self.entries.remove(&key);
                }
            }
        }
    }
}

impl ArtifactStore for IssuedArtifacts {
    fn lifetime(&self) -> Result<Duration, SamlError> {
        Ok(self.lifetime)
    }

    fn now(&self) -> Result<SystemTime, SamlError> {
        Ok((self.clock)())
    }

    fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
        let now = (self.clock)();
        self.purge_expired(now);
        if self.entries.contains_key(artifact.as_str()) {
            return Err(SamlError::Invalid(
                "artifact value is already outstanding".into(),
            ));
        }
        if entry.expires_at() <= now {
            return Ok(());
        }
        let key = artifact.as_str().to_string();
        self.expirations
            .entry(entry.expires_at())
            .or_default()
            .push(key.clone());
        self.entries.insert(key, entry);
        Ok(())
    }

    fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
        let now = (self.clock)();
        self.purge_expired(now);
        Ok(self
            .entries
            .get(artifact.as_str())
            .filter(|entry| entry.expires_at() > now)
            .cloned())
    }

    fn consume(
        &mut self,
        artifact: &Artifact,
        expected: &IssuedArtifact,
    ) -> Result<bool, SamlError> {
        let now = (self.clock)();
        self.purge_expired(now);
        if expected.expires_at() <= now {
            return Ok(false);
        }
        if self
            .entries
            .get(artifact.as_str())
            .is_some_and(|current| current == expected)
        {
            self.entries.remove(artifact.as_str());
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(Debug, thiserror::Error)]
enum IssuedArtifactsError {
    #[error("in-memory artifact store lock is poisoned")]
    Poisoned,
}

fn poisoned_lock() -> SamlError {
    SamlError::ArtifactStoreUnavailable {
        source: Box::new(IssuedArtifactsError::Poisoned),
    }
}

impl ArtifactStore for &Mutex<IssuedArtifacts> {
    fn lifetime(&self) -> Result<Duration, SamlError> {
        self.lock().map_err(|_| poisoned_lock())?.lifetime()
    }

    fn now(&self) -> Result<SystemTime, SamlError> {
        self.lock().map_err(|_| poisoned_lock())?.now()
    }

    fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
        self.lock()
            .map_err(|_| poisoned_lock())?
            .store(artifact, entry)
    }

    fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
        self.lock().map_err(|_| poisoned_lock())?.lookup(artifact)
    }

    fn consume(
        &mut self,
        artifact: &Artifact,
        expected: &IssuedArtifact,
    ) -> Result<bool, SamlError> {
        self.lock()
            .map_err(|_| poisoned_lock())?
            .consume(artifact, expected)
    }
}

impl ArtifactStore for Arc<Mutex<IssuedArtifacts>> {
    fn lifetime(&self) -> Result<Duration, SamlError> {
        self.as_ref().lifetime()
    }

    fn now(&self) -> Result<SystemTime, SamlError> {
        self.as_ref().now()
    }

    fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
        self.as_ref().store(artifact, entry)
    }

    fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
        self.as_ref().lookup(artifact)
    }

    fn consume(
        &mut self,
        artifact: &Artifact,
        expected: &IssuedArtifact,
    ) -> Result<bool, SamlError> {
        self.as_ref().consume(artifact, expected)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::artifact::encode_artifact;

    fn test_artifact(handle_seed: u32) -> Result<Artifact, SamlError> {
        let mut handle = [0u8; 20];
        handle[..4].copy_from_slice(&handle_seed.to_be_bytes());
        Artifact::try_new(encode_artifact(0, [1u8; 20], handle))
    }

    #[test]
    fn issued_artifacts_resolve_and_are_kept_only_for_the_lifetime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let lifetime = Duration::from_secs(60);
        let clock = Arc::new(AtomicU64::new(1_000));
        let store_clock = Arc::clone(&clock);
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        let sp = EntityId::try_new("https://sp.example.com/metadata")?;
        let entry = |expires_at| {
            IssuedArtifact::new(
                sp.clone(),
                String::new(),
                ArtifactChannelRequirement::Authenticated,
                expires_at,
            )
        };
        let mut issued = IssuedArtifacts::expire_after(lifetime)
            .with_clock(move || at(store_clock.load(Ordering::SeqCst)));
        let first = test_artifact(0)?;
        for n in 0u32..1_000 {
            issued.store(&test_artifact(n)?, entry(at(1_000) + lifetime))?;
        }
        clock.store(1_059, Ordering::SeqCst);
        assert!(issued.lookup(&first)?.is_some());
        clock.store(1_060, Ordering::SeqCst);
        assert!(issued.lookup(&first)?.is_none());

        let fresh = test_artifact(1_000)?;
        issued.store(&fresh, entry(at(1_060) + lifetime))?;
        assert_eq!(issued.entries.keys().collect::<Vec<_>>(), [fresh.as_str()]);
        assert_eq!(issued.expirations.len(), 1);
        Ok(())
    }
}
