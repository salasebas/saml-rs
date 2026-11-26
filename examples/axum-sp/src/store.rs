use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::SystemTime,
};

/// Values under random keys, each live until its expiry.
pub(crate) struct Store<T> {
    entries: Mutex<HashMap<String, Entry<T>>>,
}

struct Entry<T> {
    value: T,
    expires_at: SystemTime,
}

/// A lock that a panicking request handler poisoned.
#[derive(Debug)]
pub(crate) struct StoreUnavailable;

impl<T> Default for Store<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> Store<T> {
    /// Store `value` under `key` until `expires_at`, dropping expired entries.
    pub(crate) fn insert(
        &self,
        key: String,
        value: T,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<(), StoreUnavailable> {
        let mut entries = self.entries.lock().map_err(lock_poisoned)?;
        entries.retain(|_, entry| entry.is_live(now));
        entries.insert(key, Entry { value, expires_at });
        Ok(())
    }

    /// Remove the entry under `key` and return its value if it is still live.
    pub(crate) fn take_live(
        &self,
        key: &str,
        now: SystemTime,
    ) -> Result<Option<T>, StoreUnavailable> {
        let mut entries = self.entries.lock().map_err(lock_poisoned)?;
        Ok(entries
            .remove(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value))
    }

    /// The value under `key` if it is still live. An expired entry is removed.
    pub(crate) fn get_live(&self, key: &str, now: SystemTime) -> Result<Option<T>, StoreUnavailable>
    where
        T: Clone,
    {
        let mut entries = self.entries.lock().map_err(lock_poisoned)?;
        match entries.get(key) {
            Some(entry) if entry.is_live(now) => Ok(Some(entry.value.clone())),
            Some(_) => {
                entries.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

impl<T> Entry<T> {
    fn is_live(&self, now: SystemTime) -> bool {
        now < self.expires_at
    }
}

fn lock_poisoned<G>(_: PoisonError<G>) -> StoreUnavailable {
    StoreUnavailable
}
