# Browser bindings

`Outbound` holds a message that the identity provider or the service
provider sends over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign:
`redirect_url`, `post_form`, and `headers`. `Inbound::redirect`,
`Inbound::post`, `Inbound::simple_sign`, and `DeliveredArtifact` read a
received one, `RelayState` holds the relay state of every browser exchange,
and `Artifact` decodes the base64 value of an HTTP-Artifact. The flow records
keep the rules that depend on the message, such as which messages are signed,
`Destination`, endpoint selection, and how a returned `RelayState` is compared
with the pending request: see [SSO generation](web-browser-sso-generation.md),
[SSO acceptance](web-browser-sso-acceptance.md),
[Single Logout](single-logout.md),
[name identifier management](name-id-management.md), and
[HTTP-Artifact response](web-browser-sso-artifact.md).

Normative text is Bindings §§3.4 to 3.6 as corrected by Approved Errata 05
(E1, E90), RFC 2045 §6.8 for base64, and the HTTP-POST-SimpleSign
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html)
(CS-01).
[Committee Draft 04 §2.5](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html)
states how the SimpleSign signature input omits an absent `RelayState`.

The statuses hold on builds with a crypto provider. A build without one
neither signs nor verifies, so it sends HTTP-Redirect and
HTTP-POST-SimpleSign messages unsigned and refuses a signed message.

## Support

| Feature | Section | Sender | Receiver |
| --- | --- | --- | --- |
| `RelayState` with a message or an artifact | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Supported | Supported |
| HTTP-Redirect message in the query, with the DEFLATE encoding | Bindings §3.4.4, §3.4.4.1 | Supported | Supported |
| Refusing HTTP-Redirect for a message with other signed content | Bindings §3.4.4.1 | Supported | — |
| Another URL encoding, named by `SAMLEncoding` | Bindings §3.4.4 | Not supported | Not supported |
| The URL encodings an endpoint supports, in metadata | Bindings §3.4.4 | — | Not supported |
| HTTP-Redirect signature in `SigAlg` and `Signature` | Bindings §3.4.4.1 | [Partial](#detached-signatures) | [Partial](#detached-signatures) |
| HTTP-POST message in a form | Bindings §3.5.4 | Supported | Supported |
| Line-wrapped base64 in a form | Bindings §3.5.4, CS-01 §2.4 | Not supported | Supported |
| HTTP-POST-SimpleSign message in a form | CS-01 §2.4 | Supported | Supported |
| SimpleSign signature in `SigAlg` and `Signature` | CS-01 §2.4 to §2.6 | [Partial](#detached-signatures) | [Partial](#detached-signatures) |
| SimpleSign `KeyInfo` form control | CS-01 §2.4, §2.6 | Not supported | Not supported |
| `Cache-Control` and `Pragma` headers for a redirect or a form | Bindings §3.4.5.1, §3.5.5.1, §3.6.5.1, CS-01 §2.7.1 | Supported | — |
| SimpleSign endpoints in metadata | CS-01 §2.9 | — | Supported |

## Partial support

### Detached signatures

- **Supported:** the sender signs and the receiver verifies a `SigAlg`
  signature on HTTP-Redirect and HTTP-POST-SimpleSign.
- **Not supported:** RSAwithSHA1 and DSAwithSHA1, which both bindings
  require, depend on the crypto provider and its feature flags, as
  [XML Signature](xml-security-algorithms.md#xml-signature) states.

## Rules

<a id="sending-a-relaystate"></a>

### Sender: `RelayState::try_new`, `Outbound`

Code: `src/model/relay.rs`, `src/browser/outbound.rs`, `src/browser/forms.rs`

`StartSso::relay_state`, `RespondSso::relay_state`, `StartSlo::relay_state`,
and `StartNameIdManagement::relay_state` take a value built with
`RelayState::try_new`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Limit a `RelayState` this side creates to 80 bytes of UTF-8 | Mandatory | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Always |
| Refuse to send a `RelayState` in a form when it has a character outside the XML `Char` production, such as U+0000, a received one included | Mandatory | Bindings §3.5.4, §3.6.3.3, CS-01 §2.4, XML 1.0 §2.2 | Always |

### Responder: `respond_sso`, `respond_sso_artifact`, `respond_slo`, `respond_name_id_management_redirect`

Code: `src/api/idp.rs`, `src/api/slo.rs`, `src/api/name_id_management/redirect.rs`, `src/browser/outbound.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a request that carried a `RelayState` on a binding that has a `RelayState` mechanism | Mandatory | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Always |
| Return the exact `RelayState` received with the request, an empty value included | Mandatory | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Always |

### Sender: `Outbound`

Code: `src/binding/encoding.rs`, `src/browser/outbound.rs`, `src/http_header.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write the message and the detached `Signature` in base64 with its padding | Mandatory | Bindings §3.4.4.1, §3.5.4, CS-01 §2.4, §2.5, RFC 2045 §6.8 | Always |
| Return `Cache-Control: no-cache, no-store` and `Pragma: no-cache` in `Outbound::headers` for every redirect and form, an artifact delivery included | Recommended | Bindings §3.4.5.1, §3.5.5.1, §3.6.5.1, CS-01 §2.7.1 | Always |

### Sender: `Outbound::redirect_url`

Code: `src/binding/redirect.rs`, `src/binding/deflate.rs`, `src/binding/signing.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Remove a protocol `ds:Signature`, DEFLATE the rest of the XML, base64-encode it without line breaks or other whitespace, and URL-encode it into `SAMLRequest` or `SAMLResponse` | Mandatory | Bindings §3.4.4.1 | Always |
| Refuse to send a message whose content holds an XML signature other than the message's own, such as a `StartSso::extension` element with a `ds:Signature` | Recommended | Bindings §3.4.4.1 | Always |
| URL-encode a `RelayState` into its own `RelayState` parameter | Mandatory | Bindings §3.4.4.1 | Always |
| When signing, add `SigAlg`, then sign the URL-encoded `SAMLRequest` or `SAMLResponse`, `RelayState` when present, and `SigAlg`, in that order, and add the base64 `Signature` without whitespace | Mandatory | Bindings §3.4.4.1 | Always |

### Sender: `Outbound::post_form`

Code: `src/browser/outbound.rs`, `src/binding/signing.rs`, `src/binding/simplesign.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Put the base64 message in a `SAMLRequest` or `SAMLResponse` field and a present `RelayState` in a `RelayState` field of the same form, with the recipient endpoint as the form action | Mandatory | Bindings §3.5.4, CS-01 §2.4 | Always |
| To sign a SimpleSign message, sign the raw XML, then `RelayState` when present, then `SigAlg`, and send `SigAlg` and the base64 `Signature` as fields. Leave every XML signature in the message intact | Mandatory | CS-01 §2.4, §2.5, CD-04 §2.5 | Always |

<a id="base64"></a>

### Receiver: browser binding receive operations

Code: `src/binding/encoding.rs`

These rules cover the HTTP-Redirect and HTTP-POST message, the detached
`Signature` on HTTP-Redirect and HTTP-POST-SimpleSign, and the artifact in
`SAMLart` or a SOAP `ArtifactResolve`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Ignore space, tab, LF, FF, and CR in a received base64 value | Mandatory | Bindings §3.4.4.1, §3.5.4, §3.6.4, CS-01 §2.4, §2.5, RFC 2045 §6.8 | Always |

### Receiver: `Inbound::redirect`

Code: `src/browser/input.rs`, `src/flow.rs`, `src/flow/detached.rs`, `src/binding/deflate.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Raw-inflate the message when `SAMLEncoding` is absent or names DEFLATE | Mandatory | Bindings §3.4.4 | Always |
| Verify the signature over the original URL-encoded values of the parameters found by decoded name, in the order `SAMLRequest` or `SAMLResponse`, `RelayState` when present, `SigAlg`, whatever their order in the query | Mandatory | Bindings §3.4.4.1 | Always |

### Receiver: `Inbound::post`, `Inbound::simple_sign`, `DeliveredArtifact::from_form`

Code: `src/browser/input.rs`, `src/browser/artifact.rs`, `src/binding/simplesign.rs`, `src/flow/detached.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read only the SAML fields of a received form, so that no other control or submission script is needed | Mandatory | Bindings §3.5.4, §3.6.3.3, CS-01 §2.4 | Always |
| Verify a SimpleSign signature over the decoded raw XML, then `RelayState` when present, then `SigAlg` | Mandatory | CS-01 §2.5, §2.6, CD-04 §2.5 | Always |

### Receiver: `SsoEndpoint::simple_sign`, `AcsEndpoint::simple_sign`, `SloEndpoint::simple_sign`

Code: `src/browser/endpoints.rs`, `src/metadata/generate.rs`, `src/constants.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish the endpoint in the provider's metadata with the CS-01 binding URI as its `Binding` | Recommended | CS-01 §2.1, §2.9 | Always |

## Library policies

### Sender: `RelayState::try_new`, `Outbound`

Code: `src/browser/forms.rs`, `src/browser/outbound.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Refuse to send a `RelayState` in a form when it has a CR or LF outside a CRLF pair, a received one included | HTML form submission sends the character as CRLF, so the receiver would get another value and a SimpleSign signature over the sent value would fail. | Bindings §3.1.1, §3.5.4, §3.6.3.3, CS-01 §2.4 | Always |

### Responder: `respond_sso`, `respond_sso_artifact`, `respond_slo`, `respond_name_id_management_redirect`

Code: `src/model/relay.rs`, `src/browser/outbound.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Return a received `RelayState` longer than 80 bytes unchanged | The exact-return rule keeps working for a requester that exceeded the 80-byte limit, which binds only the entity that creates the value. | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |

### Sender: `Outbound::redirect_url`

Code: `src/binding/redirect.rs`, `src/binding/query.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Keep the endpoint's own query parameters before the SAML parameters, and refuse an endpoint query that already has `SAMLRequest`, `SAMLResponse`, `SAMLart`, `RelayState`, `SigAlg`, `Signature`, or `SAMLEncoding`, by decoded name | A configured parameter with one of these names could repeat a message field or be read as one by an endpoint that serves several bindings. | Bindings §3.4.4 | Always |
| Write no `SAMLEncoding` parameter, so the receiver reads DEFLATE | Every HTTP-Redirect endpoint must read DEFLATE, which an absent parameter names, so every receiver reads the message. | Bindings §3.4.4 | Always |

### Receiver: browser binding receive operations

Code: `src/binding/encoding.rs`, `src/binding/parameters.rs`, `src/model/relay.rs`, `src/browser/input.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept a received base64 value without its final `=` padding | A value from an encoder that drops the padding still decodes, as it does in OpenSAML 5.2.3. | RFC 2045 §6.8 | Always |
| Reject incomplete padding, a last character whose unused bits are not zero, and any other character outside the base64 alphabet, U+000B and non-ASCII whitespace included | No RFC 2045 encoder writes such a value, so refusing it keeps a value altered in transit from being read, as RFC 2045 §6.8 permits. | RFC 2045 §6.8 | Always |
| Reject a received `RelayState` longer than `MAX_RECEIVED_RELAY_STATE_BYTES`, 4096 bytes | The bound limits the memory that an unauthenticated value can use and still admits a value over the 80-byte limit, which binds only the creator. | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Always |
| Reject a second `RelayState`, matched by its decoded name | saml-rs compares, reports, or returns one value, and a caller's framework could read the other one. | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | Always |
| Reject a received message that also carries the message field of the other kind, such as `SAMLResponse` next to `SAMLRequest` | A typed operation reads one message kind, and with both fields the application and saml-rs could read different messages. | Bindings §3.4.4.1, §3.5.4, CS-01 §2.4 | Always |

### Receiver: `Inbound::redirect`, `DeliveredArtifact::from_query`

Code: `src/binding/query.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Read parameter names and values with form-URL-decoding, so `+` is a space and `%2B` is a plus sign | A value that the sender form-encoded, with `+` for a space, reads as sent, as it does in OpenSAML, `crewjam/saml`, and SimpleSAMLphp. | Bindings §3.4.4.1 | Always |
| Reject a received `RelayState`, or another SAML parameter the operation reads, that is not UTF-8 after decoding | `RelayState` is text, and replacing the bytes would change the value the responder returns. | Bindings §3.4.3 | Always |

### Receiver: `Inbound::redirect`

Code: `src/browser/input.rs`, `src/flow.rs`, `src/binding/deflate.rs`, `src/config/policies.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a repeated `SAMLEncoding`, or one that names another encoding, an empty value included | saml-rs implements only DEFLATE, and inflating another encoding would misread the message. | Bindings §3.4.4 | Always |
| Stop decoding when the base64-decoded or the inflated message exceeds the smaller of `XmlPolicy::redirect_inflate_max_bytes`, 1 MiB by default, and `XmlLimits::max_bytes` | The bound limits the memory and work that an unauthenticated message can cost. | Bindings §3.4.4.1 | `XmlPolicy::redirect_inflate_max_bytes`, `XmlLimits::max_bytes` |
| Reject a query that carries only one of `SigAlg` and `Signature` | Either parameter shows that the sender signed the message, so reading it as unsigned would hide a removed or broken signature. | Bindings §3.4.4.1 | Always |


### Receiver: `Inbound::simple_sign`

Code: `src/browser/input.rs`, `src/flow/detached.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Ignore a received `KeyInfo` field, and verify the signature with the keys of the peer descriptor | A key delivered through the browser is not trusted, so it cannot authenticate the sender. | CS-01 §2.6 | Always |

## Application duties

saml-rs builds the URL, the form data, and the headers, and the application
sends the HTTP response.

| Duty | Level | Section |
| --- | --- | --- |
| Send `Outbound::redirect_url` as the `Location` of an HTTP 302 or 303 response | Mandatory | Bindings §3.4.5, §3.6.5 |
| Render `Outbound::post_form` as an XHTML document whose form has `method="POST"`, `PostForm::action` as its `action`, and one control for each `PostForm::fields` entry | Mandatory | Bindings §3.5.4, §3.6.3.3, CS-01 §2.4 |
| Make those controls hidden in an HTTP-POST form and in an artifact form | Mandatory | Bindings §3.5.4, §3.6.3.3 |
| Escape each value for an XHTML attribute, quotes included | Mandatory | Bindings §3.5.4, §3.6.3.3, CS-01 §2.4 |
| Write a tab, CR, or LF in a form value as a character reference, so that a returned `RelayState` arrives unchanged | Mandatory | Bindings §3.5.3, CS-01 §2.3 |
| Keep the `enctype` of a SimpleSign form as `application/x-www-form-urlencoded`, the HTML default | Mandatory | CS-01 §2.4 |
| Send `Outbound::headers` with the redirect or the form | Recommended | Bindings §3.4.5.1, §3.5.5.1, §3.6.5.1, CS-01 §2.7.1 |
| Report no failure in SAML processing with an HTTP error status. Return a SAML response through the browser, or an application page | Mandatory | Bindings §3.4.6, §3.5.6, §3.6.6, CS-01 §2.8 |
| To refuse a message exchange, return the response with the second-level `RequestDenied` code, built with `Status::with_subordinate` | Recommended | Bindings §3.4.6, §3.5.6, §3.6.6, CS-01 §2.8 |
| Return a response to a request eventually | Recommended | Bindings §3.4.5, §3.5.5, CS-01 §2.7 |
| When a `RelayState`, or a URL derived from it, is used in a redirect or in response content, permit only safe URL schemes, such as `http` and `https` | Mandatory | Bindings §3.1.1, §3.4.5.2, §3.5.5.2, §3.6.5.2, E90 |
| Protect the integrity of a `RelayState` this side creates, by a checksum, a random reference to local state, or similar means, when no HTTP-Redirect or SimpleSign signature covers it | Recommended | Bindings §3.4.3, §3.5.3, §3.6.3.1, E1, CS-01 §2.3 |
| Do not attach sensitive state to an HTTP-POST or HTTP-Artifact `RelayState` without a further check, because an attacker can swap the `RelayState` values of two valid responses | Mandatory | Bindings §3.5.5.2, §3.6.5.2 |
| Do not use HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign for content that the user agent must not see | Recommended | Bindings §3.4.5.2, §3.5.5.2, CS-01 §2.7.2 |
| Protect these bindings with TLS when the deployment needs confidentiality in transit | Recommended | Bindings §3.4.5.2, §3.5.5.2, CS-01 §2.7.2 |
| Before deployment, analyze the chosen authentication, integrity, and confidentiality mechanisms for the exchange | Recommended | Bindings §3.4.5.2 |

CS-01 §2.4 names the SimpleSign controls without fixing their type, and hidden
controls work there too. E90 also advises, in lowercase and without an RFC 2119
level, refusing unencoded characters that could carry a cross-site scripting
attack.

## Not supported

- Advertising the supported URL encodings in metadata. Recommended when
  appropriate, Bindings §3.4.4. saml-rs reads only DEFLATE, which every
  HTTP-Redirect endpoint must support.
