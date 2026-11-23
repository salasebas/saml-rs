use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

use saml_rs::{
    AssertionId, InMemoryReplayCache, MessageId, ReplayCache, ReplayKey, ReplayPolicy, SamlError,
    SamlValidationContext,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn key(value: &str) -> Result<ReplayKey, SamlError> {
    Ok(ReplayKey::Assertion(AssertionId::try_new(value)?))
}

#[test]
fn rejects_live_duplicates_without_changing_their_deadline() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let cache_clock = Arc::clone(&clock);
    let mut cache = InMemoryReplayCache::with_clock(move || at(cache_clock.load(Ordering::SeqCst)));
    cache.check_and_store(key("_same")?, at(20))?;
    for deadline in [at(0), at(10), at(30)] {
        assert!(matches!(cache.check_and_store(key("_same")?, deadline),
            Err(SamlError::ReplayDetected { key }) if key.cache_key() == "assertion_id:_same"));
    }
    clock.store(19, Ordering::SeqCst);
    assert!(matches!(
        cache.check_and_store(key("_same")?, at(30)),
        Err(SamlError::ReplayDetected { .. })
    ));
    clock.store(20, Ordering::SeqCst);
    cache.check_and_store(key("_same")?, at(30))?;
    Ok(())
}

#[test]
fn purges_out_of_order_deadlines_before_applying_the_limit() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let cache_clock = Arc::clone(&clock);
    let mut cache = InMemoryReplayCache::with_clock(move || at(cache_clock.load(Ordering::SeqCst)))
        .with_max_entries(3);
    for (value, deadline) in [("_long", 30), ("_short", 10), ("_middle", 20)] {
        cache.check_and_store(key(value)?, at(deadline))?;
    }
    for now in [10, 20, 30] {
        clock.store(now, Ordering::SeqCst);
        cache.check_and_store(key(&format!("_new{now}"))?, at(100))?;
    }
    assert!(matches!(
        cache.check_and_store(key("_full")?, at(100)),
        Err(SamlError::ReplayCacheUnavailable { .. })
    ));
    clock.store(100, Ordering::SeqCst);
    for value in ["_new10", "_new20", "_new30"] {
        cache.check_and_store(key(value)?, at(110))?;
    }
    Ok(())
}

#[test]
fn a_full_cache_keeps_live_keys_and_does_not_store_refused_keys() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let cache_clock = Arc::clone(&clock);
    let mut cache = InMemoryReplayCache::with_clock(move || at(cache_clock.load(Ordering::SeqCst)))
        .with_max_entries(1);
    cache.check_and_store(key("_kept")?, at(10))?;
    assert!(matches!(
        cache.check_and_store(key("_refused")?, at(100)),
        Err(SamlError::ReplayCacheUnavailable { .. })
    ));
    assert!(matches!(
        cache.check_and_store(key("_kept")?, at(100)),
        Err(SamlError::ReplayDetected { .. })
    ));
    clock.store(10, Ordering::SeqCst);
    cache.check_and_store(key("_refused")?, at(100))?;
    Ok(())
}

#[test]
fn refuses_a_new_assertion_key_once_its_deadline_is_reached() -> TestResult {
    let mut cache = InMemoryReplayCache::with_clock(|| at(10));
    for deadline in [at(9), at(10)] {
        assert!(matches!(
            cache.check_and_store(key("_expired")?, deadline),
            Err(SamlError::ReplayCacheUnavailable { .. })
        ));
    }
    cache.check_and_store(key("_expired")?, at(11))?;
    Ok(())
}

#[test]
fn already_expired_keys_do_not_consume_capacity() -> TestResult {
    let mut cache = InMemoryReplayCache::with_clock(|| at(10)).with_max_entries(0);
    cache.check_and_store(ReplayKey::SsoResponse(MessageId::try_new("_past")?), at(9))?;
    assert!(matches!(
        cache.check_and_store(key("_future")?, at(11)),
        Err(SamlError::ReplayCacheUnavailable { .. })
    ));
    Ok(())
}

#[test]
fn key_families_are_independent() -> TestResult {
    let mut cache = InMemoryReplayCache::with_clock(|| at(0));
    cache.check_and_store(key("_same")?, at(10))?;
    cache.check_and_store(ReplayKey::SsoResponse(MessageId::try_new("_same")?), at(10))?;
    Ok(())
}

#[test]
fn shared_mutex_accepts_a_key_only_once_across_threads() -> TestResult {
    let now = at(0);
    let cache = Arc::new(Mutex::new(InMemoryReplayCache::with_clock(move || now)));
    let barrier = Arc::new(Barrier::new(8));
    let expires_at = now + Duration::from_secs(60);
    let mut workers = Vec::new();
    for worker_index in 0..8 {
        let mut cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let replay_key = key("_concurrent")?;
        workers.push(thread::spawn(move || {
            barrier.wait();
            if worker_index % 2 == 0 {
                cache.check_and_store(replay_key, expires_at)
            } else {
                cache.as_ref().check_and_store(replay_key, expires_at)
            }
        }));
    }
    let mut accepted = 0;
    let mut rejected = 0;
    for worker in workers {
        match worker.join().map_err(|_| "worker panicked")? {
            Ok(()) => accepted += 1,
            Err(SamlError::ReplayDetected { key })
                if key.cache_key() == "assertion_id:_concurrent" =>
            {
                rejected += 1
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!((accepted, rejected), (1, 7));
    Ok(())
}

#[test]
fn a_poisoned_mutex_refuses_cache_access() -> TestResult {
    let cache = Arc::new(Mutex::new(InMemoryReplayCache::new()));
    let worker_cache = Arc::clone(&cache);
    let worker = thread::spawn(move || -> Result<(), &'static str> {
        let _guard = worker_cache.lock().map_err(|_| "cache already poisoned")?;
        std::panic::resume_unwind(Box::new("poison cache"));
    });
    assert!(worker.join().is_err());
    let mut owned_cache = Arc::clone(&cache);
    let mut borrowed_cache = cache.as_ref();
    let adapters: [&mut dyn ReplayCache; 2] = [&mut owned_cache, &mut borrowed_cache];
    for shared_cache in adapters {
        assert!(matches!(
            shared_cache.check_and_store(
                key("_poisoned")?,
                SystemTime::now() + Duration::from_secs(60)
            ),
            Err(SamlError::ReplayCacheUnavailable { .. })
        ));
    }
    Ok(())
}

#[test]
fn replay_debug_omits_identifiers_and_does_not_read_the_clock() -> TestResult {
    let clock_reads = Arc::new(AtomicU64::new(0));
    let reads = Arc::clone(&clock_reads);
    let mut cache = InMemoryReplayCache::with_clock(move || {
        reads.fetch_add(1, Ordering::SeqCst);
        at(0)
    })
    .with_max_entries(2);
    let sensitive_id = "_private_assertion_identifier";
    cache.check_and_store(key(sensitive_id)?, at(20))?;

    let cache_debug = format!("{cache:?}");
    assert!(cache_debug.contains("InMemoryReplayCache"));
    assert!(!cache_debug.contains(sensitive_id));
    for (replay, policy_name) in [
        (ReplayPolicy::Disabled, "Disabled"),
        (ReplayPolicy::RequireCache(&mut cache), "RequireCache"),
    ] {
        let policy_debug = format!("{replay:?}");
        assert!(policy_debug.contains(policy_name));
        assert!(!policy_debug.contains(sensitive_id));
        let validation = SamlValidationContext::new(at(0), replay);
        let context_debug = format!("{validation:?}");
        assert!(context_debug.contains(&format!("replay: {policy_name}")));
        assert!(!context_debug.contains(sensitive_id));
    }
    assert_eq!(clock_reads.load(Ordering::SeqCst), 1);
    assert!(matches!(
        cache.check_and_store(key(sensitive_id)?, at(20)),
        Err(SamlError::ReplayDetected { .. })
    ));
    Ok(())
}
