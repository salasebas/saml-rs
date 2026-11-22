# Glossary

Names for the SAML roles, flows, and receiver boundaries whose protocol
obligations saml-rs models. Each entry is the term to use, then the term to
avoid when that distinction matters.

## Language

**Session Authority**:
The SAML provider that issued the authentication statement for a current
session and coordinates that session's termination.
_Avoid_: Identity Provider, when the actor-specific protocol role matters

**Session Participant**:
A SAML provider whose local session was established from an authentication
statement issued by a Session Authority.
_Avoid_: Service Provider, when the actor-specific protocol role matters

**Session-authority logout**:
A logout operation in which the Session Authority constructs the outbound
`LogoutRequest`; its obligations are narrower than those of generic logout.
_Avoid_: IdP-initiated logout, when the producer role is what matters

**Typed SLO receiver**:
An inbound Single Logout flow that carries the role, binding, local endpoint,
peer, and transaction context of the actual SAML recipient.
_Avoid_: Typed parser

**Actual recipient**:
The protocol participant operating the endpoint at which a SAML message was
received.
_Avoid_: Parser, XML consumer

**Outstanding logout**:
A `LogoutRequest` the actual recipient has accepted and that is still before
its `NotOnOrAfter`, for one principal and session. A later assertion for that
same principal and session is not accepted.
_Avoid_: session store, revoked cookie

**Validation preset**:
A bundle of validation choices. The builders use the Recommended preset. A
caller relaxes one rule by assigning the field that names it.
_Avoid_: profile, strict

**Library hardening**:
An extra rejection the SAML specifications do not require, selected by name
on top of a validation preset.
_Avoid_: strict, profile

**Name identifier management**:
The protocol by which an IdP and an SP change or end a principal's name
identifier. It belongs to the base IdP and SP operational modes.
_Avoid_: name identifier mapping

**Name identifier mapping**:
A request that an IdP Extended or SP Extended translate one name identifier
into another. It is a separate operational mode from the base IdP and SP.
_Avoid_: name identifier management

**Operational mode**:
A role in SAML V2.0 Conformance Requirements §3.1, and the full column of
features that role implements. The roles are IdP, IdP Lite, SP, SP Lite, ECP,
and the SAML authorities. Table 2 is the feature matrix for the IdP and SP
columns. IdP Lite and SP Lite are smaller columns of that table, not separate
profiles.
_Avoid_: Web Browser SSO operational mode, claimed feature

**Claimed feature**:
A SAML behaviour saml-rs already implements, bounded by role, direction,
profile or flow, and binding. It is one cell of Conformance Requirements
Table 2: a profile or message exchange plus a binding. The cells this crate
records are in `docs/conformance/`.
_Avoid_: SAML V2.0 as a whole, operational mode

**Recommended**:
The validation settings returned by `SpValidationPolicy::default()` and
`IdpValidationPolicy::default()` for claimed features.
For the obligated actor, mandatory requirements stay in force. Recommendations start enabled and can be relaxed
only by an explicit named option. A producer recommendation does not by itself
become a receiver rejection.
_Avoid_: full SAML conformance, profile

**Binding signature**:
The signature that HTTP-Redirect or HTTP-POST-SimpleSign carries in the
`Signature` and `SigAlg` parameters beside the SAML message, not inside its
XML.
_Avoid_: detached signature, in API names, because XML-DSig uses that term for
an XML signature
