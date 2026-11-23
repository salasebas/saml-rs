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

SAML builds on general specifications such as SOAP 1.1, XML Signature, XML
Schema, and HTTP. Where a SAML document states a rule for the same point, the
SAML rule governs. Where SAML says nothing, the general specification governs.
WS-I Basic Profile 1.1 is not part of SAML. Follow it only as library policy,
for interoperability, when SOAP 1.1 allows both forms. For example:

- Bindings §3.2.2 allows only SOAP 1.1. Under §3.2.2.1, as changed by E19,
  the requester puts one SAML request in the `Body`, and the responder returns
  one SAML response or a SOAP fault. Both narrow SOAP 1.1, so SAML governs.
- SOAP 1.1 §§4.2.2 and 4.2.3 govern which headers a receiver processes in
  the [supported SOAP flows](conformance/artifact-resolution.md#soap-envelope-rules).
- SOAP 1.1 §4 allows namespace-qualified elements after the `Body`. WS-I R1011
  forbids them, and rejecting them is library policy.
- Bindings §3.2.3 lets the requester send the OASIS URI as `SOAPAction` and
  forbids the responder from depending on the header. Its §3.2.3.5 example
  writes the URI without quotes. SOAP 1.1 §6.1.1 and WS-I R1109 quote it, so
  sending it bare is library policy.

## Classify the rule

A keyword alone does not classify a rule. Name the actor (producer, receiver,
identity provider, service provider, metadata publisher or consumer), the
direction (generate, accept, validate), the condition under which it applies,
and its scope (Core, a profile, a binding, a message type).

A rule for one actor does not create a rule for another. A producer `MUST`,
`MUST NOT`, or `SHOULD` does not make a receiver reject the other forms. A
receiver rejects only when a schema, a processing rule, a binding, a profile,
or a conformance requirement makes the input invalid or tells the receiver to
reject it. When a rule's condition holds, apply the rule at its stated level: a
receiver still compares an optional `Destination` when it is present.

## Implement the level

Conformance §1.2 applies the RFC 2119 keywords to every SAML V2.0
specification. The first three levels map those keywords to crate behaviour.
The fourth covers what no keyword decides.

- **Mandatory** (`MUST`, `REQUIRED`, `SHALL`, and their negations): every API
  that claims the behaviour enforces it, no policy disables it, and a required
  rejection fails closed with an explicit `SamlError`.
- **Recommended** (`SHOULD`, `RECOMMENDED`, and their negations): on by
  default. A deviation is an explicit, narrowly named option that says what it
  allows, and its rustdoc states the interoperability or security
  consequence.
- **Optional** (`MAY`, `OPTIONAL`): an intentional API, option, or feature.
  Naming a capability in the specification does not mean the crate implements
  it.
- **Library policy**: behaviour the standard leaves open, a rule stricter than
  the standard, or a resource limit. It is never presented as an OASIS
  requirement.

Scope every claim by role, direction, profile, binding, and feature. Parsing an
element or one step of a flow does not claim the whole profile.

## Record it

Each claimed flow has a record in `docs/conformance/`. The
[conformance index](../site/src/content/docs/reference/conformance.md) lists
the records and the APIs each one covers, so open only the record you need.
The site publishes them.

A record has one table row per rule, with four columns:

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| What the crate does | `Mandatory`, `Recommended`, `Optional`, or `Library policy: <reason>.` | The section, erratum, or schema type that states the rule. For library policy, the section that leaves the point open, or `—` | The option that changes it, or `Always` |

A row stays near 300 characters. Section headings name the actor and the
APIs, so the rows do not repeat them. `SamlError` variants and the order of
checks belong in the rustdoc of the API that returns them, not in a record.

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
