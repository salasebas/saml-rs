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
bindings, algorithms, and other capability lists. Leave a closed set from the
standard, such as `TopLevelStatusCode`, exhaustive.

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

Each such struct has a public way to get a value. A security policy gets it
from a named preset.

Fields stay public only while every combination of field values is valid for
the struct on its own. A check across fields belongs to the operation that
consumes the struct, such as `build()`. A struct that keeps an invariant has
private fields and `with_` setters, as [Method names](#method-names) describes.

Leave exhaustive a closed shape from the standard with no extension point,
such as `LocalizedValue`. A new field there is a breaking change.

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
