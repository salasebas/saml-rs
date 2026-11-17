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

## Method names

These rules apply when an API is added or redesigned. Rename an existing
method in the change that owns its API.

- A getter is `foo()` or `foo_mut()`, without `get_`. An in-place setter is
  `set_foo(&mut self, value)`.
- A dedicated builder configures with `foo(value)`. An owned value configures
  with `with_foo(self, value) -> Self`, which leaves `foo()` for reading.
- The primary constructor is `new`, or `try_new` when it can fail. A secondary
  constructor is `new_with_foo`, a `from_foo` conversion, or a domain name.
- A single-valued setter replaces its value. For a repeated element, the
  singular method appends one value and the plural appends an
  `impl IntoIterator<Item = T>`. Their doc comments start with `Replace`,
  `Set`, or `Append`.

## Configuration types

- A config and its builder keep their fields private, so a built config cannot
  change after `build()` validated it and a new field is not a breaking change.
- An option that relaxes a rule is named for what it allows, such as
  `AllowUnsigned`, `AllowWeakAlgorithms`, or `DoNotSign`, not for why it
  exists.
- Each hardening is its own option on `recommended()`. There is no bundled
  strict preset, because callers need the hardenings independently.
- A validation policy enum implements `Default` only when that value is its
  field in `recommended()`. Otherwise a field would get a silently different
  value from the enum than from the preset.

## Errors

- A failure that callers handle differently has its own `SamlError` variant
  with typed data, such as `Status`, `ReplayKey`, or `ResourceLimit`. Callers
  match the variant, never its message.
- A lower-level error is kept as the `source`, boxed as
  `Box<dyn Error + Send + Sync>`. A third-party type or a `From` impl from one
  never appears in `SamlError`.
- `Display` says what failed at this layer and leaves the cause to `source`.
