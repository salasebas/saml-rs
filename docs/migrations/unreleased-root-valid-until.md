# Require a `validUntil` on the metadata root

`MetadataAggregate`, `IdpDescriptor`, and `SpDescriptor` have a new
`require_root_valid_until(now, max_validity)` method. It refuses metadata
whose root element has no `validUntil`, or whose root `validUntil` lies more
than `max_validity` after `now`. A `validUntil` below the root does not count.
Import does not call the method, so existing imports behave as before.

To apply the saml2int SDP-MD03 rule, call the method right after import, with
the time that you accept the document at:

```rust
let aggregate = MetadataAggregate::from_xml(xml, trust, limits)?
    .require_root_valid_until(SystemTime::now(), Duration::from_secs(14 * 86_400))?;
```

The method returns the new `SamlError::MetadataRootValidUntilRefused`
variant. Its `reason` field is a `RootValidUntilReason`: `Missing` or
`BeyondMaxValidity`. If your code maps each `SamlError` variant to its own
response, metric, or log category, add this variant. When a refreshed
document is refused, keep the descriptors from the last accepted document
until they expire.
