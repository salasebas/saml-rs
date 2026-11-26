# Standards conformance

How `saml-rs` reads the OASIS SAML specifications when a change adds or alters
generation, parsing, validation, bindings, profiles, or metadata.

## Find the rule

Use the sources in this order for the flow under review.

1. **SAML.** Start with the [SAML 2.0 index](https://docs.oasis-open.org/security/saml/v2.0/)
   for Core, profiles, bindings, metadata, schemas, and conformance
   requirements. Apply [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
   A schema takes precedence over its listing in prose. A binding or profile
   can narrow or add to Core. For an extension, use the applicable approved
   publication in the [OASIS post-2.0 index](https://docs.oasis-open.org/security/saml/Post2.0/).
   Target a draft only for an explicitly experimental feature.
2. **Underlying standards.** Where the applicable SAML binding or profile
   leaves a point open, use the referenced version of the underlying
   specification. Start with the indexes for
   [SOAP 1.1](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/),
   [XML](https://www.w3.org/TR/xml/),
   [XML Namespaces](https://www.w3.org/TR/xml-names/),
   [XML Schema](https://www.w3.org/XML/Schema),
   [XML Signature](https://www.w3.org/TR/xmldsig-core1/),
   [XML Encryption](https://www.w3.org/TR/xmlenc-core1/), and
   [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110).
3. **Interoperability and deployment profiles.** Apply
   [WS-I Basic Profile 1.1](https://ws-i.org/Profiles/BasicProfile-1.1.html)
   as library policy where SOAP 1.1 leaves a choice and the record gives a
   reason. For a deployment profile such as
   [saml2int](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html),
   cite the specific requirement and identify the setting or deployment that
   adopts it.

The approved HTTP-POST-SimpleSign publication is
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html).
The records cite
[Committee Draft 04 §2.5](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html)
for its clarification of the signature input when RelayState is absent.

### SOAP examples

- Bindings §3.2.2 uses SOAP 1.1. Under §3.2.2.1, the requester must send one
  SAML request as the only element in the `Body`. As amended by E19, the
  responder should send a SAML response or a SOAP fault. A SAML response must
  be the only element in the `Body`.
- SOAP 1.1 §§4.2.2 and 4.2.3 govern which headers a receiver processes in
  the [supported SOAP flows](conformance/artifact-resolution.md#soap-envelope-rules).
- SOAP 1.1 §4 allows namespace-qualified elements after the `Body`. WS-I R1011
  forbids them, and rejecting them is library policy.
- [Bindings §3.2.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=11)
  lets the HTTP requester send the OASIS URI as `SOAPAction` and forbids the
  SAML responder from depending on its value.
  [SOAP 1.1 §6.1.1](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383528)
  requires the header on requests and quotes a URI value in its grammar.
  saml-rs defaults to the bare URI for interoperability. The SAML examples
  use that form, and
  [Keycloak 26.6.0](https://github.com/keycloak/keycloak/blob/26.6.0/services/src/main/java/org/keycloak/protocol/saml/SamlProtocol.java#L829-L842)
  sends it when the IdP makes a back-channel logout request to an SP.

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
  that claims the behaviour enforces the rule whenever its condition holds.
  No policy disables it. A required rejection fails closed with an explicit
  `SamlError`.
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

The [conformance index](conformance/README.md) lists the records and their
public entry points. Read the sections that cover the affected flow. The
site publishes the index and records.

A record follows the [record template](conformance/TEMPLATE.md). Its sections
are, in this order:

1. **Support.** Every feature the specification defines for the exchange,
   with one status for each actor.
2. **Partial support.** For each `Partial` feature, what the crate supports
   and what it does not.
3. **Rules.** One row for each behaviour the specification states.
4. **Library policies.** One row for each behaviour the crate adds.
5. **Application duties.** What the specification asks for and only the
   application can do.
6. **Not supported.** What a caller does in place of a missing feature.

[Identity Provider Discovery](conformance/identity-provider-discovery.md)
follows the template. The other records move to it one at a time. A record
that writes `Library policy: <reason>.` in a `Level` cell has not moved yet,
and its rows keep that form until it does.

### Support statuses

Take the features from the specification, so that a feature the crate lacks
still has a row.

- `Supported`: the crate implements the feature for this actor, and every
  Mandatory rule for it holds.
- `Partial`: the crate implements the feature with a gap. A Mandatory rule
  is unmet, a binding or a form of the message is missing, or a build lacks
  it. The record says which under **Partial support**.
- `Not supported`: the crate does not implement the feature and claims
  nothing about it.
- `—`: the specification gives this actor no part in the feature.

A duty that only the application can perform does not make a feature
`Partial`. Record it under **Application duties**.

### Rule rows

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| What the crate does | `Mandatory`, `Recommended`, or `Optional` | The section, erratum, or schema type that states the rule | The option that changes it, or `Always` |

### Library policy rows

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| What the crate does | One sentence: why the looser rule cannot be applied | The section that the policy exceeds or that leaves the point open, or `—` | The option that changes it, or `Always` |

A policy without a reason says `Reason not recorded.` Such a row is an open
question, not a decision. Report it rather than extend or defend it. When
the evidence is ambiguous, check the schemas, related OASIS documents,
errata, and the behaviour of other implementations before changing
validation. An uncertain reading does not become a new rejection.

### Wording and links

A row stays near 300 characters. Section headings name the actor and the
APIs, so the rows do not repeat them. `SamlError` variants and the order of
checks belong in the rustdoc of the API that returns them, not in a record.

Link a shared rule from each affected flow and keep its text in one record.
Add section links when readers usually need one part of a long record. Split a
record when its parts cover independently used flows or bindings. Preserve
published URLs and section links when moving those parts. When a heading
changes, keep its old link target with `<a id="old-anchor"></a>` above the
new heading.

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
