use std::collections::HashMap;
use std::io;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Barrier, Mutex,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use saml_rs::{
    Artifact, ArtifactChannelRequirement, ArtifactRelease, ArtifactStore, ArtifactWithheld,
    EntityId, IdentityProvider, IdpConfig, IssuedArtifact, IssuedArtifacts, SamlError, SsoEndpoint,
};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serialized row representing what an external database or cache persists.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializedRow {
    service_provider: String,
    message_xml: String,
    required_channel: &'static str,
    expires_at_unix_nanos: u128,
}

impl SerializedRow {
    fn from_entry(entry: &IssuedArtifact) -> Result<Self, SamlError> {
        let required_channel = match entry.required_channel() {
            ArtifactChannelRequirement::Authenticated => "authenticated",
            ArtifactChannelRequirement::Confidential => "confidential",
            _ => {
                return Err(store_err("unsupported artifact channel requirement"));
            }
        };
        let expires_at_unix_nanos = entry
            .expires_at()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| SamlError::ArtifactStoreUnavailable {
                source: Box::new(err),
            })?
            .as_nanos();
        Ok(Self {
            service_provider: entry.service_provider().as_str().to_string(),
            message_xml: entry.message_xml().to_string(),
            required_channel,
            expires_at_unix_nanos,
        })
    }

    fn into_entry(self) -> Result<IssuedArtifact, SamlError> {
        let service_provider =
            EntityId::try_new(self.service_provider).map_err(|err| store_err(err.to_string()))?;
        let required_channel = match self.required_channel {
            "authenticated" => ArtifactChannelRequirement::Authenticated,
            "confidential" => ArtifactChannelRequirement::Confidential,
            other => return Err(store_err(format!("unknown channel requirement {other}"))),
        };
        let secs = u64::try_from(self.expires_at_unix_nanos / 1_000_000_000)
            .map_err(|err| store_err(err.to_string()))?;
        let nanos = u32::try_from(self.expires_at_unix_nanos % 1_000_000_000)
            .map_err(|err| store_err(err.to_string()))?;
        let expires_at = UNIX_EPOCH + Duration::new(secs, nanos);
        Ok(IssuedArtifact::new(
            service_provider,
            self.message_xml,
            required_channel,
            expires_at,
        ))
    }
}

fn store_err(message: impl Into<String>) -> SamlError {
    SamlError::ArtifactStoreUnavailable {
        source: Box::new(io::Error::other(message.into())),
    }
}

type AfterLookupHook = Arc<dyn Fn() + Send + Sync>;

/// Shared external-style store where separate IdP nodes serialize and
/// deserialize entries through a common backend.
#[derive(Clone)]
struct SharedExternalStore {
    lifetime: Duration,
    rows: Arc<Mutex<HashMap<String, SerializedRow>>>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    lookup_calls: Arc<AtomicUsize>,
    consume_calls: Arc<AtomicUsize>,
    after_lookup: Option<AfterLookupHook>,
}

impl SharedExternalStore {
    fn new(lifetime: Duration) -> Self {
        Self {
            lifetime,
            rows: Arc::new(Mutex::new(HashMap::new())),
            clock: Arc::new(SystemTime::now),
            lookup_calls: Arc::new(AtomicUsize::new(0)),
            consume_calls: Arc::new(AtomicUsize::new(0)),
            after_lookup: None,
        }
    }

    fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    fn with_after_lookup(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.after_lookup = Some(Arc::new(hook));
        self
    }

    fn lookup_calls(&self) -> usize {
        self.lookup_calls.load(Ordering::SeqCst)
    }

    fn consume_calls(&self) -> usize {
        self.consume_calls.load(Ordering::SeqCst)
    }
}

impl ArtifactStore for SharedExternalStore {
    fn lifetime(&self) -> Result<Duration, SamlError> {
        Ok(self.lifetime)
    }

    fn now(&self) -> Result<SystemTime, SamlError> {
        Ok((self.clock)())
    }

    fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
        let now = (self.clock)();
        let row = SerializedRow::from_entry(&entry)?;
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| store_err("shared store lock poisoned"))?;
        if let Some(existing) = rows.get(artifact.as_str()).cloned() {
            if existing.into_entry()?.expires_at() > now {
                return Err(SamlError::Invalid(
                    "artifact value is already outstanding".into(),
                ));
            }
        }
        if entry.expires_at() <= now {
            rows.remove(artifact.as_str());
            return Ok(());
        }
        rows.insert(artifact.as_str().to_string(), row);
        Ok(())
    }

    fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
        self.lookup_calls.fetch_add(1, Ordering::SeqCst);
        let now = (self.clock)();
        let result = {
            let rows = self
                .rows
                .lock()
                .map_err(|_| store_err("shared store lock poisoned"))?;
            match rows.get(artifact.as_str()).cloned() {
                Some(row) => {
                    let entry = row.into_entry()?;
                    (entry.expires_at() > now).then_some(entry)
                }
                None => None,
            }
        };
        if let Some(hook) = &self.after_lookup {
            hook();
        }
        Ok(result)
    }

    fn consume(
        &mut self,
        artifact: &Artifact,
        expected: &IssuedArtifact,
    ) -> Result<bool, SamlError> {
        self.consume_calls.fetch_add(1, Ordering::SeqCst);
        let expected_row = SerializedRow::from_entry(expected)?;
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| store_err("shared store lock poisoned"))?;
        let now = (self.clock)();
        let matches = rows
            .get(artifact.as_str())
            .is_some_and(|current| current == &expected_row);
        if matches {
            rows.remove(artifact.as_str());
            return Ok(expected.expires_at() > now);
        }
        Ok(false)
    }
}

fn idp_node() -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new(RESOLUTION_URL)?,
        ))
        .build()?,
    ))
}

fn at_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn one_idp_node_issues_and_another_node_answers_from_a_shared_store() -> TestResult {
    let parties = parties()?;
    let node_a = idp_node()?;
    let node_b = idp_node()?;
    let mut store_a = SharedExternalStore::new(ARTIFACT_LIFETIME);
    let mut store_b = store_a.clone();

    let artifact =
        node_a.issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store_a)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;

    let answer = node_b.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store_b,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(answer.response().envelope())?;
    assert_eq!(resolved.local_name(), "Response");
    assert!(resolved.xml().contains(WEB_SSO_MARKER));

    let second_resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let replay = node_a.answer_artifact_resolve(
        &parties.sp_metadata,
        second_resolution.request().envelope(),
        &mut store_a,
        channel,
    )?;
    assert_eq!(
        replay.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!replay.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn two_concurrent_nodes_racing_on_one_artifact_return_the_message_only_once() -> TestResult {
    let parties = parties()?;
    let node_a = idp_node()?;
    let barrier = Arc::new(Barrier::new(2));
    let lookup_barrier = Arc::clone(&barrier);
    let mut issuer_store = SharedExternalStore::new(ARTIFACT_LIFETIME);
    let artifact = node_a.issue_artifact(
        &parties.sp_metadata,
        &web_sso_response(),
        0,
        &mut issuer_store,
    )?;

    let channel = confidential();
    let resolution_a = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let resolution_b = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let req_a = resolution_a.request().envelope().to_string();
    let req_b = resolution_b.request().envelope().to_string();
    let sp_xml = parties.sp.metadata_xml().to_string();

    // Synchronize inside lookup so both nodes deterministically read the entry
    // before either attempts the atomic consume.
    let racing_store = issuer_store.with_after_lookup(move || {
        lookup_barrier.wait();
    });

    let mut handles = Vec::new();
    for request_envelope in [req_a, req_b] {
        let mut store = racing_store.clone();
        let sp_xml = sp_xml.clone();
        handles.push(thread::spawn(move || -> Result<ArtifactRelease, String> {
            let node = idp_node().map_err(|err| err.to_string())?;
            let sp = SpDescriptor::from_metadata_xml(
                EntityId::try_new(SP_ENTITY_ID).map_err(|err| err.to_string())?,
                &sp_xml,
                MetadataTrustPolicy::Unverified,
            )
            .map_err(|err| err.to_string())?;
            let answer = node
                .answer_artifact_resolve(&sp, &request_envelope, &mut store, channel)
                .map_err(|err| err.to_string())?;
            if answer.release() == ArtifactRelease::Returned {
                if !answer.response().envelope().contains(WEB_SSO_MARKER) {
                    return Err("returned response omitted the stored message".into());
                }
            } else if answer.response().envelope().contains(WEB_SSO_MARKER) {
                return Err("withheld response leaked the stored message".into());
            }
            Ok(answer.release())
        }));
    }

    let mut returned = 0usize;
    let mut not_outstanding = 0usize;
    for handle in handles {
        match handle.join().map_err(|_| "responder thread panicked")?? {
            ArtifactRelease::Returned => returned += 1,
            ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding) => not_outstanding += 1,
            other => return Err(format!("unexpected artifact release: {other:?}").into()),
        }
    }
    assert_eq!((returned, not_outstanding), (1, 1));
    assert_eq!(racing_store.lookup_calls(), 2);
    assert_eq!(racing_store.consume_calls(), 2);
    Ok(())
}

#[test]
fn shared_mutex_issued_artifacts_returns_a_message_only_once_across_threads() -> TestResult {
    let parties = parties()?;
    let shared = Arc::new(Mutex::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME)));
    let mut issuer_store = Arc::clone(&shared);
    let artifact = parties.idp.issue_artifact(
        &parties.sp_metadata,
        &web_sso_response(),
        0,
        &mut issuer_store,
    )?;

    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let request_envelope = resolution.request().envelope().to_string();
    let sp_xml = parties.sp.metadata_xml().to_string();

    let worker_count = 6usize;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut workers = Vec::new();
    for index in 0..worker_count {
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        let request_envelope = request_envelope.clone();
        let sp_xml = sp_xml.clone();
        workers.push(thread::spawn(move || -> Result<ArtifactRelease, String> {
            let node = idp_node().map_err(|err| err.to_string())?;
            let sp = SpDescriptor::from_metadata_xml(
                EntityId::try_new(SP_ENTITY_ID).map_err(|err| err.to_string())?,
                &sp_xml,
                MetadataTrustPolicy::Unverified,
            )
            .map_err(|err| err.to_string())?;
            barrier.wait();
            let answer = if index % 2 == 0 {
                let mut owned = Arc::clone(&shared);
                node.answer_artifact_resolve(&sp, &request_envelope, &mut owned, channel)
            } else {
                let mut borrowed = shared.as_ref();
                node.answer_artifact_resolve(&sp, &request_envelope, &mut borrowed, channel)
            }
            .map_err(|err| err.to_string())?;
            Ok(answer.release())
        }));
    }

    let mut returned = 0usize;
    let mut not_outstanding = 0usize;
    for worker in workers {
        match worker.join().map_err(|_| "worker panicked")?? {
            ArtifactRelease::Returned => returned += 1,
            ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding) => not_outstanding += 1,
            other => return Err(format!("unexpected release: {other:?}").into()),
        }
    }
    assert_eq!((returned, not_outstanding), (1, worker_count - 1));
    Ok(())
}

#[test]
fn withheld_requests_never_consume_the_artifact_from_the_store() -> TestResult {
    let parties = parties()?;
    let mut store = SharedExternalStore::new(ARTIFACT_LIFETIME);
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;

    let hostile = parties.other.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    assert_eq!(
        parties
            .idp
            .answer_artifact_resolve(
                &parties.other_metadata,
                hostile.request().envelope(),
                &mut store,
                channel,
            )?
            .release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DifferentPresenter)
    );
    assert_eq!(
        parties
            .idp
            .answer_artifact_resolve(
                &parties.sp_metadata,
                resolution.request().envelope(),
                &mut store,
                authenticated_without_confidentiality(),
            )?
            .release(),
        ArtifactRelease::Withheld(ArtifactWithheld::InsufficientChannelProtection)
    );
    let wrong_destination = resolution.request().envelope().replace(
        &format!("Destination=\"{RESOLUTION_URL}\""),
        "Destination=\"https://idp.example.com/other\"",
    );
    assert_eq!(
        parties
            .idp
            .answer_artifact_resolve(
                &parties.sp_metadata,
                &wrong_destination,
                &mut store,
                channel,
            )?
            .release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DestinationMismatch)
    );
    assert_eq!(store.consume_calls(), 0);

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    assert_eq!(store.consume_calls(), 1);
    Ok(())
}

#[test]
fn conditional_consume_does_not_delete_a_replaced_entry() -> TestResult {
    let parties = parties()?;
    let now = at_secs(1_000);
    let original = IssuedArtifact::new(
        EntityId::try_new(SP_ENTITY_ID)?,
        web_sso_response(),
        ArtifactChannelRequirement::Confidential,
        now + ARTIFACT_LIFETIME,
    );
    let replacement = IssuedArtifact::new(
        EntityId::try_new(OTHER_ENTITY_ID)?,
        logout_request(),
        ArtifactChannelRequirement::Authenticated,
        now + Duration::from_secs(120),
    );

    struct MutatingAfterLookup {
        inner: IssuedArtifacts,
        replacement: Option<IssuedArtifact>,
    }

    impl ArtifactStore for MutatingAfterLookup {
        fn lifetime(&self) -> Result<Duration, SamlError> {
            self.inner.lifetime()
        }

        fn now(&self) -> Result<SystemTime, SamlError> {
            self.inner.now()
        }

        fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
            self.inner.store(artifact, entry)
        }

        fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
            let found = self.inner.lookup(artifact)?;
            if let Some(next) = self.replacement.take() {
                self.inner.remove(artifact);
                self.inner.store(artifact, next)?;
            }
            Ok(found)
        }

        fn consume(
            &mut self,
            artifact: &Artifact,
            expected: &IssuedArtifact,
        ) -> Result<bool, SamlError> {
            self.inner.consume(artifact, expected)
        }
    }

    let mut store = MutatingAfterLookup {
        inner: IssuedArtifacts::expire_after(ARTIFACT_LIFETIME).with_clock(move || now),
        replacement: Some(replacement.clone()),
    };
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store)?;
    assert_eq!(
        store
            .inner
            .lookup(&artifact)?
            .as_ref()
            .map(IssuedArtifact::service_provider),
        Some(original.service_provider())
    );

    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    assert_eq!(store.inner.lookup(&artifact)?, Some(replacement));
    Ok(())
}

#[test]
fn expiration_between_lookup_and_consume_withholds_the_message() -> TestResult {
    let parties = parties()?;
    let clock = Arc::new(AtomicU64::new(1_000));
    let store_clock = Arc::clone(&clock);
    let advance_clock = Arc::clone(&clock);
    let mut store = SharedExternalStore::new(Duration::from_secs(60))
        .with_clock(move || at_secs(store_clock.load(Ordering::SeqCst)))
        .with_after_lookup(move || {
            advance_clock.store(1_060, Ordering::SeqCst);
        });

    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn expiration_at_consume_time_withholds_the_message() -> TestResult {
    struct ExpireOnConsume {
        inner: IssuedArtifacts,
        clock: Arc<AtomicU64>,
        consume_calls: usize,
    }

    impl ArtifactStore for ExpireOnConsume {
        fn lifetime(&self) -> Result<Duration, SamlError> {
            self.inner.lifetime()
        }

        fn now(&self) -> Result<SystemTime, SamlError> {
            self.inner.now()
        }

        fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
            self.inner.store(artifact, entry)
        }

        fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
            self.inner.lookup(artifact)
        }

        fn consume(
            &mut self,
            artifact: &Artifact,
            expected: &IssuedArtifact,
        ) -> Result<bool, SamlError> {
            self.consume_calls += 1;
            self.clock.store(1_060, Ordering::SeqCst);
            self.inner.consume(artifact, expected)
        }
    }

    let parties = parties()?;
    let clock = Arc::new(AtomicU64::new(1_000));
    let store_clock = Arc::clone(&clock);
    let mut store = ExpireOnConsume {
        inner: IssuedArtifacts::expire_after(Duration::from_secs(60))
            .with_clock(move || at_secs(store_clock.load(Ordering::SeqCst))),
        clock,
        consume_calls: 0,
    };

    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    )?;
    assert_eq!(store.consume_calls, 1);
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn existing_caller_wrappers_and_auto_traits_remain_compatible() -> TestResult {
    use std::cell::RefCell;
    use std::panic::{RefUnwindSafe, UnwindSafe};
    use std::sync::RwLock;

    fn assert_auto_traits<T: Send + Sync + UnwindSafe + RefUnwindSafe>() {}
    assert_auto_traits::<IssuedArtifacts>();
    assert_auto_traits::<IssuedArtifact>();
    assert_auto_traits::<ArtifactChannelRequirement>();

    let parties = parties()?;
    let channel = confidential();

    // MutexGuard<IssuedArtifacts>
    let mutex = Mutex::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME));
    {
        let mut guard = mutex.lock().map_err(|_| "mutex poisoned")?;
        let artifact =
            parties
                .idp
                .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut guard)?;
        let resolution = parties.sp.resolve_artifact(
            &parties.idp_metadata,
            &artifact,
            channel,
            without_replay_cache(),
        )?;
        let answer = parties.idp.answer_artifact_resolve(
            &parties.sp_metadata,
            resolution.request().envelope(),
            &mut guard,
            channel,
        )?;
        assert_eq!(answer.release(), ArtifactRelease::Returned);
    }

    // RwLockWriteGuard<IssuedArtifacts>
    let rwlock = RwLock::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME));
    {
        let mut guard = rwlock.write().map_err(|_| "rwlock poisoned")?;
        let artifact =
            parties
                .idp
                .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut guard)?;
        let resolution = parties.sp.resolve_artifact(
            &parties.idp_metadata,
            &artifact,
            channel,
            without_replay_cache(),
        )?;
        let answer = parties.idp.answer_artifact_resolve(
            &parties.sp_metadata,
            resolution.request().envelope(),
            &mut guard,
            channel,
        )?;
        assert_eq!(answer.release(), ArtifactRelease::Returned);
    }

    // Box<IssuedArtifacts>
    let mut boxed = Box::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME));
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut boxed)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut boxed,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);

    // RefMut<IssuedArtifacts>
    let cell = RefCell::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME));
    let mut borrowed = cell.borrow_mut();
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut borrowed)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut borrowed,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    Ok(())
}

#[test]
fn storage_failures_fail_closed_without_releasing_an_unconsumed_artifact() -> TestResult {
    #[derive(Clone, Copy)]
    enum FailurePoint {
        None,
        Lifetime,
        Now,
        Store,
        Lookup,
        Consume,
    }

    struct FaultyStore {
        inner: IssuedArtifacts,
        fail: FailurePoint,
    }

    impl ArtifactStore for FaultyStore {
        fn lifetime(&self) -> Result<Duration, SamlError> {
            if matches!(self.fail, FailurePoint::Lifetime) {
                return Err(store_err("lifetime unavailable"));
            }
            self.inner.lifetime()
        }

        fn now(&self) -> Result<SystemTime, SamlError> {
            if matches!(self.fail, FailurePoint::Now) {
                return Err(store_err("clock unavailable"));
            }
            self.inner.now()
        }

        fn store(&mut self, artifact: &Artifact, entry: IssuedArtifact) -> Result<(), SamlError> {
            if matches!(self.fail, FailurePoint::Store) {
                return Err(store_err("write failed"));
            }
            self.inner.store(artifact, entry)
        }

        fn lookup(&mut self, artifact: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
            if matches!(self.fail, FailurePoint::Lookup) {
                return Err(store_err("read failed"));
            }
            self.inner.lookup(artifact)
        }

        fn consume(
            &mut self,
            artifact: &Artifact,
            expected: &IssuedArtifact,
        ) -> Result<bool, SamlError> {
            if matches!(self.fail, FailurePoint::Consume) {
                return Err(store_err("delete failed"));
            }
            self.inner.consume(artifact, expected)
        }
    }

    let parties = parties()?;
    let mut store = FaultyStore {
        inner: IssuedArtifacts::expire_after(ARTIFACT_LIFETIME),
        fail: FailurePoint::Store,
    };
    let store_failed =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store);
    assert!(matches!(
        store_failed,
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));

    store.fail = FailurePoint::Lifetime;
    assert!(matches!(
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store),
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));

    store.fail = FailurePoint::Now;
    assert!(matches!(
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store),
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));

    store.fail = FailurePoint::None;
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut store)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;

    store.fail = FailurePoint::Lookup;
    let lookup_failed = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    );
    assert!(matches!(
        lookup_failed,
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));

    store.fail = FailurePoint::Consume;
    let consume_failed = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    );
    assert!(matches!(
        consume_failed,
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));

    // The artifact was never consumed during the failed attempts.
    store.fail = FailurePoint::None;
    let recovered = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut store,
        channel,
    )?;
    assert_eq!(recovered.release(), ArtifactRelease::Returned);
    assert!(recovered.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn poisoned_mutex_artifact_store_fails_closed() -> TestResult {
    let parties = parties()?;
    let shared = Arc::new(Mutex::new(IssuedArtifacts::expire_after(ARTIFACT_LIFETIME)));
    let mut issuer = Arc::clone(&shared);
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, &mut issuer)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;

    let worker_store = Arc::clone(&shared);
    let worker = thread::spawn(move || -> Result<(), &'static str> {
        let _guard = worker_store.lock().map_err(|_| "store already poisoned")?;
        std::panic::resume_unwind(Box::new("poison artifact store"));
    });
    assert!(worker.join().is_err());

    let mut owned = Arc::clone(&shared);
    let mut borrowed = shared.as_ref();
    let stores: [&mut dyn ArtifactStore; 2] = [&mut owned, &mut borrowed];
    for store in stores {
        assert!(matches!(
            parties
                .idp
                .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, store),
            Err(SamlError::ArtifactStoreUnavailable { .. })
        ));
        assert!(matches!(
            parties.idp.answer_artifact_resolve(
                &parties.sp_metadata,
                resolution.request().envelope(),
                store,
                channel,
            ),
            Err(SamlError::ArtifactStoreUnavailable { .. })
        ));
    }
    Ok(())
}

#[test]
fn issued_artifacts_clock_expiry_debug_redaction_and_dynamic_dispatch() -> TestResult {
    let parties = parties()?;
    let clock = Arc::new(AtomicU64::new(100));
    let reads = Arc::new(AtomicUsize::new(0));
    let store_clock = Arc::clone(&clock);
    let clock_reads = Arc::clone(&reads);
    let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60)).with_clock(move || {
        clock_reads.fetch_add(1, Ordering::SeqCst);
        at_secs(store_clock.load(Ordering::SeqCst))
    });

    let dyn_store: &mut dyn ArtifactStore = &mut issued;
    let artifact =
        parties
            .idp
            .issue_artifact(&parties.sp_metadata, &web_sso_response(), 0, dyn_store)?;
    let entry = dyn_store
        .lookup(&artifact)?
        .ok_or("artifact should be outstanding")?;
    assert_eq!(entry.expires_at(), at_secs(160));
    assert_eq!(
        entry.required_channel(),
        ArtifactChannelRequirement::Confidential
    );

    let reads_before_debug = reads.load(Ordering::SeqCst);
    let entry_debug = format!("{entry:?}");
    assert!(entry_debug.contains("IssuedArtifact"));
    assert!(!entry_debug.contains(WEB_SSO_MARKER));
    let store_debug = format!("{issued:?}");
    assert!(store_debug.contains("IssuedArtifacts"));
    assert!(!store_debug.contains(artifact.as_str()));
    assert!(!store_debug.contains(WEB_SSO_MARKER));
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_debug);

    // Duplicate live key is rejected without replacing the entry.
    assert!(matches!(
        issued.store(&artifact, entry.clone()),
        Err(SamlError::Invalid(_))
    ));

    // At 159s (1s before expiry) it is still outstanding; at 160s it expires.
    clock.store(159, Ordering::SeqCst);
    assert!(issued.lookup(&artifact)?.is_some());
    clock.store(160, Ordering::SeqCst);
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!issued.remove(&artifact));

    // Re-inserting with a later expiry is not evicted when an older bucket drains.
    clock.store(200, Ordering::SeqCst);
    let first = IssuedArtifact::new(
        EntityId::try_new(SP_ENTITY_ID)?,
        web_sso_response(),
        ArtifactChannelRequirement::Confidential,
        at_secs(210),
    );
    let later = IssuedArtifact::new(
        EntityId::try_new(SP_ENTITY_ID)?,
        logout_request(),
        ArtifactChannelRequirement::Authenticated,
        at_secs(260),
    );
    issued.store(&artifact, first)?;
    assert!(issued.remove(&artifact));
    issued.store(&artifact, later.clone())?;
    clock.store(210, Ordering::SeqCst);
    assert_eq!(issued.lookup(&artifact)?, Some(later));
    Ok(())
}

#[cfg(crypto)]
#[test]
fn web_browser_sso_artifact_flows_work_across_two_idp_nodes_with_a_shared_store() -> TestResult {
    use saml_rs::{
        ArtifactDelivery, CertificatePem, Credentials, DeliveredArtifact, Inbound, NameId,
        NameIdFormat, PrivateKeyPem, RespondSso, SsoAssertion, SsoResponseBinding, StartSso,
        X509Credential,
    };

    let cert = CertificatePem::new(include_str!(
        "../fixtures/key/sp/cert.unencrypted.pkcs8.cer"
    ));
    let key = PrivateKeyPem::new(include_str!(
        "../fixtures/key/sp/privkey.unencrypted.pkcs8.pem"
    ));
    let creds = Credentials::default().with_signing_credential(X509Credential::new(cert, key));
    let build_idp = || -> Result<IdentityProvider, Box<dyn std::error::Error>> {
        Ok(IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::redirect("https://idp.example.com/sso")?,
            )
            .credentials(creds.clone())
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new(RESOLUTION_URL)?,
            ))
            .build()?,
        ))
    };

    let node_a = build_idp()?;
    let node_b = build_idp()?;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::artifact("https://sp.example.com/acs")?,
        )
        .build()?,
    );
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        node_a.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;

    let mut store_a = SharedExternalStore::new(ARTIFACT_LIFETIME);
    let mut store_b = store_a.clone();
    let channel = confidential();

    // 1. SP-initiated SSO via respond_sso_artifact on node A, resolved on node B.
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().response_binding(SsoResponseBinding::Artifact),
    )?;
    let query = started
        .outbound
        .redirect_url()?
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or("redirect URL has no query")?;
    let received = node_a.receive_sso(
        &sp_descriptor,
        Inbound::redirect(query),
        without_replay_cache(),
    )?;
    let outbound = node_a.respond_sso_artifact(
        &sp_descriptor,
        &received,
        SsoAssertion::new(NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)),
        RespondSso::artifact(ArtifactDelivery::redirect(0)),
        &mut store_a,
    )?;
    let artifact_query = outbound
        .redirect_url()?
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or("artifact redirect URL has no query")?;
    let delivered = DeliveredArtifact::from_query(artifact_query)?;
    let resolution = sp.resolve_artifact(
        &idp_descriptor,
        delivered.artifact(),
        channel,
        without_replay_cache(),
    )?;
    let answer = node_b.answer_artifact_resolve(
        &sp_descriptor,
        resolution.request().envelope(),
        &mut store_b,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(answer.response().envelope())?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::artifact(delivered, resolved),
        without_replay_cache(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    // 2. IdP-initiated SSO via initiate_sso_artifact on node A, resolved on node B.
    let unsolicited = node_a.initiate_sso_artifact(
        &sp_descriptor,
        SsoAssertion::new(NameId::new("bob@example.com")),
        RespondSso::artifact(ArtifactDelivery::post_form(0)),
        &mut store_a,
    )?;
    let delivered = DeliveredArtifact::from_form(unsolicited.post_form()?.fields())?;
    let resolution = sp.resolve_artifact(
        &idp_descriptor,
        delivered.artifact(),
        channel,
        without_replay_cache(),
    )?;
    let answer = node_b.answer_artifact_resolve(
        &sp_descriptor,
        resolution.request().envelope(),
        &mut store_b,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(answer.response().envelope())?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::artifact(delivered, resolved),
        without_replay_cache(),
    )?;
    assert_eq!(session.name_id().value(), "bob@example.com");

    // 3. Store write failures surface as ArtifactStoreUnavailable on SSO artifact flows.
    struct UnavailableStore;
    impl ArtifactStore for UnavailableStore {
        fn lifetime(&self) -> Result<Duration, SamlError> {
            Ok(ARTIFACT_LIFETIME)
        }
        fn store(&mut self, _: &Artifact, _: IssuedArtifact) -> Result<(), SamlError> {
            Err(store_err("backend write unavailable"))
        }
        fn lookup(&mut self, _: &Artifact) -> Result<Option<IssuedArtifact>, SamlError> {
            Err(store_err("backend read unavailable"))
        }
        fn consume(&mut self, _: &Artifact, _: &IssuedArtifact) -> Result<bool, SamlError> {
            Err(store_err("backend consume unavailable"))
        }
    }
    let mut unavailable = UnavailableStore;
    assert!(matches!(
        node_a.respond_sso_artifact(
            &sp_descriptor,
            &received,
            SsoAssertion::new(
                NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
            ),
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            &mut unavailable,
        ),
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));
    assert!(matches!(
        node_a.initiate_sso_artifact(
            &sp_descriptor,
            SsoAssertion::new(NameId::new("bob@example.com")),
            RespondSso::artifact(ArtifactDelivery::post_form(0)),
            &mut unavailable,
        ),
        Err(SamlError::ArtifactStoreUnavailable { .. })
    ));
    Ok(())
}
