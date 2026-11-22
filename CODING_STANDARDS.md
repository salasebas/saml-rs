# Coding standards

## Doc comments

A doc comment says what the caller can do with the item.

The OASIS section, the obligated actor, and a note that a check is library
policy go in the pull request or in `docs/`.

## Caller-visible changes

The same pull request updates `docs/migrations/` when a caller must change
code, handle a new error, or extend an exhaustive `match`. A new public enum
variant is that change.

Follow [How to add a migration guide](CONTRIBUTING.md#how-to-add-a-migration-guide).
A compatible addition stays in the commit message. release-plz writes
`CHANGELOG.md`.

## Stricter than the cited section

When the diff rejects a message the cited section accepts, the pull request
says so in its own sentence: library policy, the section it exceeds, and why
the looser rule cannot be applied.

## Public enums that can grow

Put `#[non_exhaustive]` on a public enum whose set can grow: errors, reasons,
bindings, algorithms, validation and encryption policies, and other capability
lists. Leave a closed set from the standard, such as `TopLevelStatusCode`,
exhaustive.

Also mark each variant with named fields that only this crate builds, so a
later field is not a breaking change. A variant that a public trait asks
callers to return, such as `SamlError::ReplayDetected` for `ReplayCache`,
stays constructible.

## Public structs that can grow

Put `#[non_exhaustive]` on a public struct with public fields whose set can
grow: policies, limits, options, generation inputs, and results that only this
crate builds. A caller takes the value from a preset, `Default`, or a
constructor and assigns the fields it changes, so a later field is not a
breaking change. A result comes from the operation that returns it.

Each such struct has a public way to get a value: `Default` or a constructor.
A validation policy also has named presets, and its `Default` is the
recommended one.

Fields stay public while the struct guarantees nothing about their values. The
operation that consumes the struct, such as `build()`, checks them. A struct
that keeps an invariant itself has private fields and `with_` setters, as
[Method names](#method-names) describes.

Leave exhaustive a closed shape from the standard with no extension point,
such as `LocalizedValue`. A new field there is a breaking change.

## Stored snapshots

A pending snapshot struct is a stored format. With the `serde` feature, a
deployment keeps the JSON in its session store across an upgrade and a
rollback.
[Serialize pending snapshots with `serde`](site/src/content/docs/reference/features.md#serialize-pending-snapshots-with-serde)
states the rules that callers rely on.

- A new field is optional. Leave it out of `new`, give it
  `#[cfg_attr(feature = "serde", serde(default))]`, and make its absent value
  mean the behaviour before the field existed. Data that an older release
  stored then still reads.
- Keep the name of each field and the values it reads. The name is the key in
  the stored data.
- Do not add `deny_unknown_fields`. An older release reads data that a newer
  release wrote.
- The JSON in `tests/pending_snapshot_serde.rs` is the data that deployments
  hold. When one of those tests fails, change the code. Edit the JSON only to
  add a new optional field.

## Type names

- When each role has its own type for one concept, the type name carries the
  role: `SpConfig` and `IdpConfig`, `SpMetadata` and `IdpMetadata`,
  `ServiceProvider` and `IdentityProvider`.
- A crate-private type in a role module leaves the role out of its name.
  Other modules write it with its module, such as `sp::Engine` and
  `idp::Engine`.

## Method names

These rules apply when an API is added or redesigned.

- Name an item for the value it returns or the action it performs. Give it
  the name of a sibling item only when both mean the same thing, such as one
  SAML attribute read from two types. When the precise name differs from the
  siblings' names, use the precise name: `PendingAuthnRequest::idp_entity_id()`
  next to `PendingLogoutRequest::peer_entity_id()`.
- A value the crate cannot guarantee or never reads is deleted, not renamed.
- A value that is not a dedicated builder configures with
  `with_foo(self, value) -> Self`, which leaves `foo()` for reading.
- A single-valued setter replaces its value. For a repeated element, the
  singular method appends one value and the plural appends an
  `impl IntoIterator<Item = T>`. Their doc comments start with `Replace`,
  `Set`, or `Append`.

## Configuration types

- An option that relaxes a rule is named for what it allows, such as
  `AllowUnsigned`, `AllowWeakAlgorithms`, or `DoNotSign`, not for why it
  exists.
- Each hardening is a separate option on the type that owns its check, such as
  a field of `SpValidationPolicy` or `SamlValidationContext::with_authn_request_age`.
  There is no bundled strict preset, because callers need the hardenings
  independently.
- A validation policy enum implements `Default` only when that value is its
  field in `recommended()`. Otherwise a field would get a silently different
  value from the enum than from the preset.

## Errors

- A failure that callers handle differently gets its own `SamlError` variant
  with typed data, such as `Status`, `ReplayKey`, or `ResourceLimit`, instead
  of `Invalid(String)`. Callers match the variant, never its message.
- A lower-level error is kept as the `source`, boxed as
  `Box<dyn Error + Send + Sync>`. A third-party type or a `From` impl from one
  never appears in `SamlError`.
- `Display` says what failed at this layer and leaves the cause to `source`.
