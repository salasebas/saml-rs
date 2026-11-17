# 6. Single Logout and name identifier management

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Section |
| --- | --- |
| A received logout `NameID` keeps its attributes | [6.1](#61-compare-the-received-nameid-with-its-attributes) |
| A hand-built `FlowResult` needs its status | [6.2](#62-add-the-status-to-a-hand-built-flowresult) |
| A logout response may use another front-channel binding | [6.3](#63-accept-a-logout-response-over-another-front-channel-binding) |
| An undecryptable `EncryptedID` no longer fails `receive_slo` | [6.4](#64-answer-a-logout-request-whose-encryptedid-does-not-decrypt) |
| `ManageNameIDRequest` children must be in schema order | [6.5](#65-order-the-children-of-a-managenameidrequest) |
| Subordinate status codes use the `anyURI` rule | [6.6](#66-check-custom-subordinate-status-codes-against-the-uri-rule) |

`RespondSlo::relay_state` is in [section 1.3](compile-errors.md#13-drop-respondslorelay_state).
A RelayState a responder adds is in
[section 3.8](sp-sso.md#38-read-the-relaystate-a-peer-adds-to-a-response).

## 6.1 Compare the received NameID with its attributes

**Affects:** code that reads a typed `LogoutRequest` NameID.

**Before:** `LogoutRequest::name_id` returned the value with no attributes.
**Now:** it returns the `Format`, `NameQualifier`, `SPNameQualifier`, and
`SPProvidedID` of the received `<NameID>`.

- A comparison with `==` includes every attribute, so a stored `NameId`
  without the attributes the peer sends no longer compares equal. Store the
  `NameId` from the accepted assertion, which carries the same attributes, or
  compare `NameId::value` when your session lookup is by value only.
- An `OutstandingLogout` built from the received `NameId` carries its
  `Format`. A later assertion matches only when it has the same `Format`, as
  Core §3.3.4 strong matching requires. Before, a value match was enough. An
  `unspecified` `Format` still compares values only, because an omitted
  `Format` means `unspecified` (Core §2.2.2).

## 6.2 Add the status to a hand-built `FlowResult`

**Affects:** code that builds a typed `LogoutResponse` from a `FlowResult` it
assembled itself. A `FlowResult` returned by the raw logout parsers already
carries these fields. `LogoutResponse::status` is a compatible addition.

**Now:** `LogoutResponse::try_from(FlowResult)` reads the top-level status code
from the extract. It returns `SamlError::ProtocolProfile` when `statusCode` is
missing, or is not `Success`, `Requester`, `Responder`, or `VersionMismatch`.

**Upgrade:** add the top-level code, and the subordinate code when the response
has one:

```rust
use saml_rs::constants::status_code;
use saml_rs::util::Value;

let status_fields = [
	("statusCode".to_string(), Value::Str(status_code::SUCCESS.to_string())),
	(
		"subordinateStatusCode".to_string(),
		Value::Str(status_code::PARTIAL_LOGOUT.to_string()),
	),
];
```

## 6.3 Accept a logout response over another front-channel binding

**Affects:** `finish_slo`. See
[Single Logout rules](../../conformance/single-logout.md).

**Before:** a response over a different binding than the request returned
`SamlError::UnsupportedBinding`.
**Now:** a response to an HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign
request is accepted over any of those three bindings, as Profiles §4.4.3.4 and
§4.4.3.5 allow. The `Destination` is checked against your
`SingleLogoutService` for the binding the response arrived on. A response over
a front-channel binding your metadata does not publish returns
`SamlError::MissingMetadata`. A SOAP response to a front-channel request, or a
front-channel response to a SOAP request, still returns
`SamlError::UnsupportedBinding`.

**Upgrade:** if you relied on that error to refuse a binding, stop publishing a
`SingleLogoutService` for it.

## 6.4 Answer a logout request whose `EncryptedID` does not decrypt

**Affects:** `receive_slo` with a `decryption_key` configured. See
[encrypted principal identifier](../../conformance/single-logout.md#encrypted-principal-identifier).

**Before:** an authenticated `LogoutRequest` whose `EncryptedID` no
configured key decrypts returned the decryption error, for example
`SamlError::Crypto` for a key that does not match or an unsupported algorithm,
or `SamlError::Unsupported` for RSA-v1.5 key transport that is not allowed.
**Now:** it returns `Ok` with a `Received<LogoutRequest>` whose `name_id()` is
`None`, as it already did with no decryption key. The `SessionIndex` values
are still returned. A decryption key that does not load, an `EncryptedID`
without exactly one `EncryptedData`, and plaintext that is not one `NameID`
still return an error.

**Upgrade:** check `name_id()` before you invalidate sessions. To report the
unknown principal, answer with an error status:

```rust
use saml_rs::{RespondSlo, Status, SubordinateStatusCode};

let options = RespondSlo::post()
    .status(Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal()));
```

## 6.5 Order the children of a `ManageNameIDRequest`

**Affects:** identity providers that call `receive_name_id_management`, and
either role calling `receive_name_id_management_redirect`.

**Before:** `Issuer`, `ds:Signature`, and `Extensions` were skipped wherever
they appeared.
**Now:** a received `ManageNameIDRequest` must follow the protocol schema
sequence: at most one `Issuer`, one `ds:Signature`, and one `Extensions`, in
that order, then the identifier and the change. Another order, such as
`Extensions` after `Terminate` or before `Issuer`, or a second `Issuer`,
`Signature`, or `Extensions`, returns `SamlError::ProtocolProfile`.

**Upgrade:** ask a peer that sends another order to send the schema order.

## 6.6 Check custom subordinate status codes against the URI rule

**Affects:** your own URI passed to `SubordinateStatusCode::try_new`, and a
custom `LogoutResponse` template that writes `Consent`, a `StatusCode`
`Value`, or the `Issuer`.

**Before:** these values were parsed as WHATWG URLs.
**Now:** they are read as an absolute URI reference by the rule a NameID
`Format` already follows: RFC 2396 with RFC 2732 IPv6 hosts, after the
`xs:anyURI` escaping of XML Schema 1.0. `try_new` still rejects whitespace and
`&`, `"`, `'`, `<`, and `>`, and the outbound check still rejects whitespace.
`Destination` is still parsed as a URL.

`try_new` now returns `SamlError::Invalid`, and `respond_slo` returns
`SamlError::ProtocolProfile` from its outbound check, for a value that:

- has nothing after the scheme, such as `urn:` or `mailto:`;
- has a `%` not followed by two hexadecimal digits, such as `urn:example:%zz`;
- has a second `#`, such as `urn:example:a#b#c`;
- has `[` or `]` in a path or at the start of an opaque part, such as
  `https://idp.example/a[b]` or `urn:[a]`;
- has a character XML 1.0 cannot carry, such as U+0001.

Before, these were accepted, and a non-XML character produced a message the
peer could not parse. A value with a host or port the URL parser refused, such
as an empty host, a non-numeric port, or a port above 65535
(`https://idp.example:70000/status`), is now accepted.

**Upgrade:** percent-encode the character as `%HH`, or use a URI such as
`urn:example:status:local-failure`.
