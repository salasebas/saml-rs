# 3. Service provider

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Section |
| --- | --- |
| The Response `Issuer` is checked on success | [3.1](#31-send-the-identity-providers-entity-id-as-the-response-issuer) |
| An error status is reported only after correlation | [3.2](#32-handle-correlation-errors-on-an-sso-error-response) |
| A future bearer `NotBefore` is rejected | [3.3](#33-expect-a-future-bearer-notbefore-to-be-rejected) |
| `InResponseTo=""` on unsolicited SSO is rejected | [3.4](#34-reject-an-empty-inresponseto-on-typed-unsolicited-sso) |
| `with_recipient_endpoint` applies to unsolicited SSO | [3.5](#35-supply-a-published-acs-to-accept_unsolicited_sso) |
| Attributes are split by `Name` and `NameFormat` | [3.6](#36-read-each-attribute-by-name-and-nameformat) |
| A signed `AuthnRequest` is allowed when the IdP does not require one | [3.7](#37-stop-relying-on-the-signing-flag-conflict-when-the-idp-does-not-require-signing) |
| A RelayState the responder adds is accepted | [3.8](#38-read-the-relaystate-a-peer-adds-to-a-response) |
| Replay storage ignores an unparsable extra `NotOnOrAfter` | [3.9](#39-expect-an-unevaluated-bearer-notonorafter-to-pass-replay-storage) |
| CBC detection follows the decryptor's XML interpretation | [3.10](#310-sign-cbc-responses-regardless-of-xml-spelling) |

Sections 3.1 to 3.3 apply to `finish_sso`, `finish_sso_with_outstanding_logout`,
`accept_unsolicited_sso`, `accept_unsolicited_sso_with_outstanding_logout`,
`finish_paos_sso`, and the raw `parse_login_response`,
`parse_login_response_with_request_id`, `parse_unsolicited_login_response`,
and `flow` with `ParserType::SamlResponse`.

## 3.1 Send the identity provider's entity ID as the Response `Issuer`

**Affects:** identity providers that write a Response `Issuer` other than the
entity ID in their metadata. For raw `flow`, this applies with `from_issuer`.

**Before:** on a successful response only the assertion `Issuer` was
compared. **Now:** the Response `Issuer` gets the check that an error response
already got.

| Successful response | Before | Now |
| --- | --- | --- |
| Response `Issuer` is not the identity provider | Accepted | `IssuerMismatch` with that issuer |
| More than one Response `Issuer` | Accepted | `IssuerMismatch` without an issuer |
| No Response `Issuer` | Accepted | Accepted |

A response with a verified Response signature changes only when the identity
provider signed another `Issuer` itself.

**Upgrade:** correct the identity provider's issuer, or build the
`IdpDescriptor` for the entity ID it sends.

## 3.2 Handle correlation errors on an SSO error response

**Affects:** code that matches `StatusNotSuccess` to show a login failure from
the identity provider.

**Before:** the status came first. **Now:** a `Response` with a status other
than `Success` returns `SamlError::StatusNotSuccess` only after a present
signature verifies and its `Issuer`, `InResponseTo`, and `Destination` checks
pass. The response still does not need a signature, and a missing `Issuer` is
accepted.

| Error response | Before | Now |
| --- | --- | --- |
| Present signature does not verify | `StatusNotSuccess` | `SignatureVerification` |
| Wrong `Issuer` | `StatusNotSuccess` | `IssuerMismatch` |
| Wrong or missing `InResponseTo` | `StatusNotSuccess` | `InResponseToMismatch` |
| Wrong `Destination`, or signed without one | `StatusNotSuccess` | `DestinationMismatch` |

**Upgrade:** treat these errors as a failed login too. `StatusNotSuccess` now
means the response came for this login and this service provider. Without a
signature it is still not proof of who sent it.

## 3.3 Expect a future bearer `NotBefore` to be rejected

**Affects:** service providers whose identity provider sends a bearer
`SubjectConfirmationData@NotBefore`.

**Before:** the attribute was ignored. **Now:** it is checked when present.

- A `NotBefore` later than now plus the `NotBefore` clock skew, or one that
  cannot be read as a timestamp, no longer confirms the assertion. When no
  other bearer confirmation is satisfied, the response fails with
  `SamlError::SubjectConfirmationInvalid` and
  `SubjectConfirmationReason::TimeWindowInvalid`.
- A namespace-qualified `NotBefore` attribute on `SubjectConfirmationData`
  returns `SamlError::ProtocolProfile`, as qualified copies of the other
  attributes the library reads already do.
- A `NotBefore` that has been reached is still accepted.

**Upgrade:** synchronize the clocks, or widen
`ClockSkew::with_not_before_millis`.

## 3.4 Reject an empty `InResponseTo` on typed unsolicited SSO

**Affects:** `accept_unsolicited_sso` and
`accept_unsolicited_sso_with_outstanding_logout`.

**Before:** an empty attribute was read as absent and the response was
accepted. **Now:** a `Response` or bearer `SubjectConfirmationData` with
`InResponseTo=""` returns `SamlError::InResponseToMismatch` with
`expected: None` and `actual: Some("")`.

**Upgrade:** ask the identity provider to omit the attribute. Until it does,
the raw `parse_unsolicited_login_response` still reads an empty value as
absent. saml-rs identity providers stopped writing it
([section 4.5](idp-sso.md#45-expect-unsolicited-responses-without-inresponseto)).

## 3.5 Supply a published ACS to `accept_unsolicited_sso`

**Affects:** callers that pass `SamlValidationContext::with_recipient_endpoint`
to `accept_unsolicited_sso` or `accept_unsolicited_sso_with_outstanding_logout`.
See [Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md).

**Before:** the URL was ignored, and the response had to name the default
assertion consumer for its binding. **Now:** an unsolicited response's
`Destination` and bearer `Recipient` are compared with the supplied URL. A
response sent to another assertion consumer you publish is accepted when you
supply that consumer's URL.

- A supplied URL that your metadata does not publish as an
  `AssertionConsumerService` for the incoming binding returns
  `SamlError::Invalid`.
- A response that names another assertion consumer than the supplied one
  returns `SamlError::DestinationMismatch`.

**Upgrade:** pass the URL of the endpoint that received the request, taken
from your HTTP routing, or leave it unset to compare with the default
assertion consumer.

## 3.6 Read each attribute by `Name` and `NameFormat`

**Affects:** code that reads `SsoSession::attributes`, the raw
`attributeNameFormats` extract, or builds a `FlowResult` and converts it to
`SsoSession`.

**Before:** `<Attribute>` elements with the same `Name` and different
`NameFormat` were one entry with the `NameFormat` of the first element and the
values of all of them. The values of a repeated element after the first were
dropped when that element had more than one value.
**Now:** they are separate `Attribute` entries, as Errata 05 E49 identifies an
attribute by both. An omitted `NameFormat` and `unspecified` are still one
attribute. Every value of repeated elements with the same `Name` and
`NameFormat` is kept.

`Attributes::get` returns the first entry with a name. If an identity provider
sends one name in more than one format, look it up by both:

```rust
let role = session.attributes().as_slice().iter().find(|attribute| {
	attribute.name() == "role" && attribute.format() == Some(&AttributeNameFormat::Uri)
});
```

Raw extracts:

- Each `attributeNameFormats` entry of `FlowResult::extract` now has an
  `attributeValue` array with the element's values. Allow the new key when you
  compare or iterate over those entries.
- A hand-built `FlowResult` converted to `SsoSession` needs an
  `attributeNameFormats` entry per `<Attribute>`, with `name`, `nameFormat`
  when it has one, and `attributeValue`. The typed attributes come from those
  entries. An extract with `attributes` and no `attributeNameFormats`, or an
  entry without `attributeValue`, returns `SamlError::Invalid`.

## 3.7 Stop relying on the signing-flag conflict when the IdP does not require signing

**Affects:** a service provider that signs AuthnRequests, through
`AuthnRequestSigningPolicy::Sign` or `AuthnRequestsSigned="true"` in its raw
metadata, and calls `start_sso` or `create_login_request` for an identity
provider whose `WantAuthnRequestsSigned` is false or omitted. See
[Web Browser SSO generation](../../conformance/web-browser-sso-generation.md#service-provider-authnrequest).

**Before:** the call returned `SamlError::Invalid` with
`ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG` and built no request.
**Now:** it returns a signed request. A service provider that does not sign
still gets that error when the identity provider's `WantAuthnRequestsSigned`
is true.

**Upgrade:** remove handling written for the signing case. A service provider
that should send unsigned requests leaves `AuthnRequestSigningPolicy::Sign`
unset.

## 3.8 Read the RelayState a peer adds to a response

**Affects:** `finish_sso`, `finish_slo`, and
`finish_name_id_management_redirect`. See
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md),
[Single Logout rules](../../conformance/single-logout.md), and
[name identifier management](../../conformance/name-id-management.md).

**Before:** when the request carried no RelayState, a response with one
returned `SamlError::RelayStateMismatch`.
**Now:** that response is accepted, empty or not, as Bindings §3.4.3 and
§3.5.3 let the responder add one. A response that changes, empties, or drops a
RelayState the request carried still returns that error.

The received value is reported by `SsoSession::relay_state`,
`LogoutCompleted::relay_state`, and the return value of
`finish_name_id_management_redirect`
([section 1.9](compile-errors.md#19-bind-the-relaystate-from-finish_name_id_management_redirect)).

**Upgrade:** if you sent no RelayState and treat its absence as part of your
state, inspect the reported value before you act on it. Treat it as untrusted
input, and sanitize a URL taken from it before you redirect.

## 3.9 Expect an unevaluated bearer `NotOnOrAfter` to pass replay storage

**Affects:** `finish_sso` or `accept_unsolicited_sso` under
`ReplayPolicy::RequireCache`, and direct calls to
`SsoSession::check_and_store_replay`. See
[metadata and replay](../../conformance/metadata-and-replay.md#replay).

**Before:** a bearer confirmation whose `NotOnOrAfter` did not parse returned
`SamlError::TimeWindowInvalid` with `TimeWindowField::ReplayExpiration` after
every other check had passed, while the same response was accepted under
`DisabledForCompatibility`.
**Now:** the session assertion gets its replay deadline by the rule the other
assertions already used: the latest bearer
`SubjectConfirmationData@NotOnOrAfter` that parses as an instant. A
confirmation whose value does not parse is ignored when another one parses.
A response with one bearer confirmation is not affected.

**Upgrade:** none. Such a response is now accepted, and its identifiers are
stored.

## 3.10 Sign CBC responses regardless of XML spelling

**Affects:** typed SP acceptance with
`ResponseSignaturePolicy::RequireForEncryptedCbc`, including Recommended.
The same algorithm reader also applies to an IdP's unsigned requested
`EncryptedID`.

**Before:** namespace declarations, prefixed attributes, or a foreign-namespace
`EncryptionMethod` could hide the algorithm from the Response signature check.
AES-192-CBC was also missed.
**Now:** the check uses the same namespace-complete encrypted wrapper,
namespace-aware element selection, and attribute interpretation as the decryptor.
AES-128-CBC, AES-192-CBC, AES-256-CBC, and Triple DES require a verified Response
signature before decryption. A missing method or algorithm returns
`SamlError::Crypto`. An unknown data algorithm returns `SamlError::Unsupported`.

**Upgrade:** sign the outer Response when using CBC. The existing
`AllowUnsignedEncryptedCbc` relaxation remains available for deployments that
explicitly accept the risk. AES-GCM still permits an unsigned Response carrying
a signed assertion. This implements the relying-party recommendation in
[Approved Errata 05 E93](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html),
which replaces Core §6.2 and updates Profiles §4.1.3.5 and §4.1.4.3.
An unsigned requested `EncryptedID` whose canonicalized method names CBC
stays unread, including when a prefixed attribute names GCM before it.
