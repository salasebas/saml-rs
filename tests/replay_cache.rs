use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

use saml_rs::{AssertionId, InMemoryReplayCache, MessageId, ReplayCache, ReplayKey, SamlError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn key(value: &str) -> Result<ReplayKey, SamlError> {
    Ok(ReplayKey::AssertionId(AssertionId::try_new(value)?))
}

#[test]
fn rejects_live_duplicates_without_changing_their_deadline() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let cache_clock = Arc::clone(&clock);
    let mut cache = InMemoryReplayCache::with_clock(move || at(cache_clock.load(Ordering::SeqCst)));
    cache.check_and_store(key("_same")?, at(20))?;
    for deadline in [at(0), at(10), at(30)] {
        assert!(matches!(cache.check_and_store(key("_same")?, deadline),
            Err(SamlError::ReplayDetected { key }) if key == "assertion_id:_same"));
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
        Err(SamlError::Invalid(_))
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
        Err(SamlError::Invalid(_))
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
fn already_expired_keys_do_not_consume_capacity() -> TestResult {
    let mut cache = InMemoryReplayCache::with_clock(|| at(10)).with_max_entries(0);
    cache.check_and_store(key("_past")?, at(9))?;
    cache.check_and_store(key("_present")?, at(10))?;
    assert!(matches!(
        cache.check_and_store(key("_future")?, at(11)),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn key_families_are_independent() -> TestResult {
    let mut cache = InMemoryReplayCache::with_clock(|| at(0));
    cache.check_and_store(key("_same")?, at(10))?;
    cache.check_and_store(ReplayKey::ResponseId(MessageId::try_new("_same")?), at(10))?;
    Ok(())
}

#[test]
fn shared_mutex_accepts_a_key_only_once_across_threads() -> TestResult {
    let cache = Arc::new(Mutex::new(InMemoryReplayCache::new()));
    let barrier = Arc::new(Barrier::new(8));
    let expires_at = SystemTime::now() + Duration::from_secs(60);
    let mut workers = Vec::new();
    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let replay_key = key("_concurrent")?;
        workers.push(thread::spawn(move || {
            barrier.wait();
            let mut shared_cache = cache.as_ref();
            shared_cache.check_and_store(replay_key, expires_at)
        }));
    }
    let mut accepted = 0;
    let mut rejected = 0;
    for worker in workers {
        match worker.join().map_err(|_| "worker panicked")? {
            Ok(()) => accepted += 1,
            Err(SamlError::ReplayDetected { key }) if key == "assertion_id:_concurrent" => {
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
    let mut shared_cache = cache.as_ref();
    assert!(matches!(
        shared_cache.check_and_store(
            key("_poisoned")?,
            SystemTime::now() + Duration::from_secs(60)
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}
