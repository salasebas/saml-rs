# How to upgrade from 0.2 to 0.3

Upgrade from the latest `0.2` release to `0.3`. This release does not change
feature flags or the minimum supported Rust version. The
[changelog](../../../CHANGELOG.md) lists every other change.

## Topics

- [Update response signing](response-signatures.md)
- [Replace public `time` types with `std::time`](time-and-replay.md)

## Checklist

- Replace `MessageSignaturePolicy` and `SpValidationPolicy::messages`.
- Replace public `OffsetDateTime` validation values with `SystemTime`.
- Replace public `time::Duration` replay values with `std::time::Duration`.
- Update every `ReplayCache::check_and_store` implementation.
- Update raw `FlowOptions::now` assignments.
- Remove a direct `time` dependency when no application code still uses it.
- Choose embedded Response signing for typed IdP HTTP-POST output, or opt out
  for a legacy CBC peer.
- Run validation and replay tests, including fixed-clock and expiration cases.

[All migration guides](../README.md)
