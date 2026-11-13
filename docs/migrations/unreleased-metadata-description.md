# Complete metadata configuration literals

**Affects:** callers that construct typed or raw `SpMetadataConfig` or
`IdpMetadataConfig` by naming every field, including through the compatibility
crates. This change is unreleased.

Add these fields to keep the previous output:

```rust
organization: None,
contacts: Vec::new(),
error_url: None,
```

Typed callers can use `SpMetadataConfig::new(acs_endpoints)` or
`IdpMetadataConfig::new(sso_endpoints)` instead. Raw callers can end a literal
with `..Default::default()`. Existing config builder calls need no change.

When you populate the new fields, generation validates organization
cardinality, XML Schema language tags, `mailto:` email URIs, absolute
organization and error URIs, and XML characters. Invalid inputs return
`SamlError::Invalid`. Leaving the fields empty preserves existing output and
validation.
