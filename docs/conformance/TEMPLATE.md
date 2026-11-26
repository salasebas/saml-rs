<!--
Record template.

1. Copy this file to docs/conformance/<record>.md.
2. Replace every <...>, and delete these comments.
3. Delete a section that has no content. Keep "Support".
4. Add the record to docs/conformance/README.md and to
   site/versions/next/conformance.mjs.

docs/standards-conformance.md, "Record it", defines each status, each
level, and how to word a row. identity-provider-discovery.md is a record in
this layout.
-->

# <Exchange, binding, or shared layer>

<Two or three sentences. Name the public entry points, the roles, and the
bindings this record covers. Name the normative documents, and the errata
that change them.>

## Support

<!--
One row per feature that the specification defines for this exchange: each
message, each binding that can carry it, each optional element or capability.
Take the features from the specification, not from the code, so that a
feature the crate lacks still has a row.

One status column per actor. Name each column for its actor: "Identity
provider" and "Service provider", or "Requester" and "Responder", or
"Signer" and "Verifier". Use a second table, under its own
level-three heading, when part of the record has different actors.

A status is `Supported`, `Partial`, `Not supported`, or `—`. `Supported`
covers every build and every form of the feature that the row names. When
only part of that works, the status is `Partial`. Link a `Partial` cell to
its entry under "Partial support".
-->

| Feature | Section | <Actor> | <Actor> |
| --- | --- | --- | --- |
| <Feature> | <Section> | Supported | Not supported |
| <Feature> | <Section> | [Partial](#<feature-anchor>) | — |

## Partial support

<!--
One entry per `Partial` cell. Say what works, what does not, and for whom.
Name the builds when support depends on a crypto provider or feature.
-->

### <Feature>

- **Supported:** <what the crate does>.
- **Not supported:** <what is missing, and what a caller or peer sees>.

## Rules

<!--
The behaviour that the specification states for a `Supported` or `Partial`
feature. One subsection per actor and public API. One behaviour per row.
`Level` is `Mandatory`, `Recommended`, or `Optional`. `Option` names the
setting that changes the behaviour, or says `Always`.
-->

### <Actor>: `<public_api>`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| <What the crate does> | Mandatory | <Section> | Always |

## Library policies

<!--
Behaviour that the crate adds: a point the specification leaves open, a rule
stricter than the specification, or a resource limit. `Reason` is one
sentence that says why the looser rule cannot be applied. `Section` is the
clause that the policy exceeds or that leaves the point open, or `—`.
Write `Reason not recorded.` for a policy whose reason is unknown. Such a
row is an open question, not a decision.
-->

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| <What the crate does> | <Why the looser rule cannot be applied.> | <Section> | Always |

## Application duties

<!--
What the specification requires, recommends, or permits and the crate cannot
do, because the application owns the HTTP exchange, the session, or the
storage. `Level` is `Mandatory`, `Recommended`, or `Optional`. A duty does
not make a feature `Partial`.
-->

| Duty | Level | Section |
| --- | --- | --- |
| <What the application does> | Mandatory | <Section> |

## Not supported

<!--
One item per `Not supported` cell that needs more than its status: what the
caller does instead, or which document defines the feature.
-->

- <Feature>. <What the caller does instead.>
