# Replace public `time` types with `std::time`

[How to upgrade from 0.2 to 0.3](README.md)

Public validation and replay APIs now take [`std::time::SystemTime`] and
[`std::time::Duration`]. Parsing still uses the `time` crate internally. The
affected APIs are:

- `SamlValidationContext::new` and `SamlValidationContext::now`;
- `SamlValidationContext::with_replay_retention` and
  `SamlValidationContext::replay_retention`;
- `ReplayCache::check_and_store`;
- `FlowOptions::now` on the raw compatibility API.

An unsupported validation instant now returns `SamlError` instead of
panicking. An invalid or unrepresentable replay expiration, including zero
retention and a retention that overflows `SystemTime`, returns
`SamlError::TimeWindowInvalid` with `TimeWindowField::ReplayExpiration`.

## Update validation clocks and replay retention

Replace `OffsetDateTime::now_utc()` with `SystemTime::now()`, and replace
`time::Duration` constructors with `std::time::Duration`.

Before:

```rust
use saml_rs::{ReplayPolicy, SamlValidationContext};
use time::{Duration, OffsetDateTime};

let validation = SamlValidationContext::new(
    OffsetDateTime::now_utc(),
    ReplayPolicy::DisabledForCompatibility,
)
.with_replay_retention(Duration::minutes(5));
```

After:

```rust
use std::time::{Duration, SystemTime};

use saml_rs::{ReplayPolicy, SamlValidationContext};

let validation = SamlValidationContext::new(
    SystemTime::now(),
    ReplayPolicy::DisabledForCompatibility,
)
.with_replay_retention(Duration::from_secs(5 * 60));
```

Build a fixed test clock from `SystemTime::UNIX_EPOCH` with `checked_add` or
`checked_sub`.

## Update `ReplayCache` implementations

`check_and_store` now takes a `SystemTime` expiration.

Before:

```rust
use saml_rs::{ReplayCache, ReplayKey, SamlError};
use time::OffsetDateTime;

struct Cache;

impl ReplayCache for Cache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), SamlError> {
        let _ = (key, expires_at);
        Ok(())
    }
}
```

After:

```rust
use std::time::SystemTime;

use saml_rs::{ReplayCache, ReplayKey, SamlError};

struct Cache;

impl ReplayCache for Cache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: SystemTime,
    ) -> Result<(), SamlError> {
        let _ = (key, expires_at);
        Ok(())
    }
}
```

Store the key and expiration atomically. If the cache uses another timestamp
type, convert at the storage boundary. Keep subsecond precision, and keep
instants before the Unix epoch when the backend can store them.

## Update raw `FlowOptions`

Assign a `SystemTime` when you pin the validation instant:

```rust
use std::time::SystemTime;

use saml_rs::raw::FlowOptions;

let mut options = FlowOptions::default();
options.now = Some(SystemTime::now());
```

Drop a direct `time` dependency after every call site has moved, if the
application used `time` only for these APIs. Keep it when the rest of the
application still needs it.

[`std::time::Duration`]: https://doc.rust-lang.org/std/time/struct.Duration.html
[`std::time::SystemTime`]: https://doc.rust-lang.org/std/time/struct.SystemTime.html
