# Standards conformance

How `saml-rs` reads the OASIS SAML specifications when a change adds or alters
generation, parsing, validation, bindings, profiles, or metadata.

## Find the rule

The source for a behaviour is the approved specification, schema, and errata
that govern it. The SAML V2.0 set is listed in
[Conformance Requirements](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
and the [OASIS document and schema index](https://docs.oasis-open.org/security/saml/v2.0/).
The documents most changes need are
[Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
[Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf),
[Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
[Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf),
and [approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
A schema takes precedence over a schema listing in prose. A binding or
profile can narrow or add to Core. A draft is a target only for a feature that
is explicitly experimental.

## Classify the rule

A keyword alone does not classify a rule. Name the actor (producer, receiver,
identity provider, service provider, metadata publisher or consumer), the
direction (generate, accept, validate), the condition under which it applies,
and its scope (Core, a profile, a binding, a message type).

A rule for one actor does not create a rule for another. A producer `MUST`,
`MUST NOT`, or `SHOULD` does not make a receiver reject the other forms. A
receiver rejects only when a schema, a processing rule, a binding, a profile,
or a conformance requirement makes the input invalid or tells the receiver to
reject it. A conditional rule is mandatory whenever its condition holds: an
optional `Destination` is still compared when it is present.

## Implement the level

- **Mandatory** (`MUST`, `REQUIRED`, `SHALL`, and their negations): every API
  that claims the behaviour enforces it, no policy disables it, and a required
  rejection fails closed with an explicit `SamlError`.
- **Recommended** (`SHOULD`, `RECOMMENDED`, and their negations): on by
  default. A deviation is an explicit, narrowly named option that says what it
  allows.
- **Optional** (`MAY`, `OPTIONAL`): an intentional API, option, or feature.
  Naming a capability in the specification does not mean the crate implements
  it.
- **Library policy**: behaviour the standard leaves open, a rule stricter than
  the standard, or a resource limit. It is never presented as an OASIS
  requirement.

Scope every claim by role, direction, profile, binding, and feature. Parsing an
element or one step of a flow does not claim the whole profile.

## Record it

Each claimed flow has a record in `docs/conformance/`, one row per rule: the
rule, its level, the section that states it, and the option that controls it.
The site publishes these records.

A library-policy row states its reason in one sentence: why the looser rule
cannot be applied. A row without a reason is an open question, not a decision.
Report it rather than extend or defend it. When the evidence is ambiguous,
check the schemas, related OASIS documents, errata, and the behaviour of other
implementations before changing validation. An uncertain reading does not
become a new rejection.

## Review checklist

1. Which section, schema declaration, binding, profile, or erratum governs the
   behaviour, and which claimed flow does it affect?
2. Who is obligated, under which condition, and does the text require
   generation, acceptance, verification, or rejection?
3. Does the change enforce only that requirement? A stricter receiver rule is
   library policy, stated in its own sentence in the pull request
   ([coding standards](../CODING_STANDARDS.md#stricter-than-the-cited-section)).
4. Is a recommendation on by default, and an optional behaviour opt-in?
5. Do focused tests cover the boundary of the rule, accepting and rejecting?
