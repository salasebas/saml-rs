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
