<!--
Record template.

1. Copy this file to docs/conformance/<record>.md.
2. Replace every <...>, and delete these comments.
3. Delete a section that has no content. Keep "Support" unless no
   specification defines the record's features.
4. Add the record to docs/conformance/README.md and to
   site/versions/next/conformance.mjs.

docs/standards-conformance.md, "Record it", defines each status and each
level, says where a behaviour goes, and says how to word a row, a note, and
a Code line. identity-provider-discovery.md is a record in this layout.
-->

# <Exchange, binding, or shared layer>

<!--
Keep this Code line when the same files perform every row of Rules and
Library policies, and delete the Code lines under the headings below. Otherwise delete this
one. List the files under src/ that do the work, not a file that only
passes a call through.
-->

Code: `<src/file.rs>`

<Two or three sentences. Name the public entry points, the roles, and the
bindings this record covers.>

<Normative text is ... Name the normative documents, and the errata that
change them.>

<!--
Keep this paragraph when a build without a crypto provider lacks a feature
of this record, and delete it otherwise. Keep its first sentence. In at most
two more, say what that build cannot do in the record's flows and what the
public APIs return or refuse there.
-->

The statuses hold on builds with a crypto provider. <What a build without
one cannot do in this record's flows, and what the APIs return or refuse.>

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

A status is `Supported`, `Partial`, `Not supported`, or `—`, and it
describes the builds with a crypto provider. `Supported` covers every such
build, whatever its provider and feature flags, and every form of the
feature that the row names. When only part of that works, the status is
`Partial`. A build without a crypto provider makes no cell `Partial`. Link a
`Partial` cell to its entry under "Partial support".
-->

| Feature | Section | <Actor> | <Actor> |
| --- | --- | --- | --- |
| <Feature> | <Section> | Supported | Not supported |
| <Feature> | <Section> | [Partial](#<feature-anchor>) | — |

## Partial support

<!--
One entry per `Partial` cell, or one for several cells that one gap
explains. Say what works, what does not, and for whom. Name the builds when
support differs between crypto providers or feature flags.
-->

### <Feature>

- **Supported:** <what the crate does>.
- **Not supported:** <what is missing, and what a caller or peer sees>.

## Rules

<!--
The behaviour that the specification states and the crate performs, for a
`Supported` or `Partial` feature. An optional behaviour that the caller turns
on is a rule too. One subsection per actor and public API, or per kind of
operation. One behaviour per row. `Level` is `Mandatory`, `Recommended`, or
`Optional`. `Option` names the setting that changes the behaviour, or says
`Always`.

A note holds what no row can hold, in one paragraph of at most three
sentences. Before the table, it states what every row shares. After the
table, it states how the record reads an unclear clause, what another
implementation does at a named version, or where another record keeps a
shared rule.
-->

### <Actor>: `<public_api>`

Code: `<src/file.rs>`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| <What the crate does> | Mandatory | <Section> | Always |

## Library policies

<!--
Behaviour that the crate adds: a point the specification leaves open, a rule
stricter than the specification, or a resource limit. `Reason` is one
sentence that says what the policy protects or keeps working. `Section` is
the clause that the policy exceeds or that leaves the point open, or `—`.
Write `Reason not recorded.` for a policy whose reason is unknown. Such a
row is an open question, not a decision.

Use the actor and API headings of Rules. Use one table with no heading when
the record has one actor and one API, or when each policy applies to every
operation that handles what the policy names. That table's Code line goes
directly under "## Library policies". Level-three topic headings can split
that table, each with its own Code line.
-->

### <Actor>: `<public_api>`

Code: `<src/file.rs>`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| <What the crate does> | <What the policy protects or keeps working.> | <Section> | Always |

## Application duties

<!--
A step of a supported feature that the specification asks of the actor or
the deployment and that no crate API performs, because the application owns
the HTTP exchange, the session, or the storage. When the application uses a
value that a crate API returns, name that API in the duty. `Level` is
`Mandatory`, `Recommended`, or `Optional`. A duty does not make a feature
`Partial`.
-->

| Duty | Level | Section |
| --- | --- | --- |
| <What the application does, naming the crate API whose value it uses> | Mandatory | <Section> |

## Not supported

<!--
One item per `Not supported` cell whose feature is Mandatory, whose caller
does something in its place, or that another document defines. One item can
cover several cells when it names the actor and each missing feature. Give the
level and section when the specification sets a level, then what the caller
does instead or which document defines the feature.
-->

- <Feature>. <Level>, <Section>. <What the caller does instead.>
