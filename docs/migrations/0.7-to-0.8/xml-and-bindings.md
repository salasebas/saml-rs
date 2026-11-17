# 7. XML, SOAP, and bindings

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Section |
| --- | --- |
| Malformed or namespace-malformed XML is rejected everywhere | [7.1](#71-send-well-formed-namespace-well-formed-xml) |
| Line breaks in received text become line feeds | [7.2](#72-expect-a-line-feed-for-each-line-break-in-received-text) |
| SOAP envelopes and SimpleSign messages use your `XmlPolicy::limits` | [7.3](#73-size-xmlpolicylimits-for-soap-envelopes-and-simplesign-messages) |
| One SOAP `Header` before the `Body` | [7.4](#74-send-one-soap-header-before-the-body) |
| Signatures in SOAP messages are verified in place | [7.5](#75-expect-signatures-in-soap-messages-to-be-verified-where-they-sit) |
| PAOS refuses `mustUnderstand` headers | [7.6](#76-handle-refused-soap-headers-on-paos-logins) |
| `base64_decode` ignores only ASCII whitespace | [7.7](#77-remove-unicode-whitespace-before-base64_decode) |
| A received RelayState may be up to 4096 bytes | [7.8](#78-accept-a-received-relaystate-longer-than-80-bytes) |
| One RelayState per message | [7.9](#79-send-one-relaystate-per-message) |
| Inbound decryption has a configurable aggregate work limit | [7.10](#710-keep-encrypted-messages-within-the-decryption-work-limit) |
| Processed signatures need same-document references and covered content | [7.11](#711-check-xml-signature-references-and-coverage) |

## 7.1 Send well-formed, namespace-well-formed XML

**Affects:** every input `saml-rs` parses: received messages, metadata, SOAP and
PAOS envelopes, `saml_rs::context::is_valid_xml`, and
`saml_rs::xml::dom::parse`, `parse_with_limits`, `parse_roots`, and
`parse_roots_with_limits`. Well-formed input is not affected.

**Before:** the DOM accepted these inputs, and only the parser behind signature
verification and decryption rejected them.
**Now:** they return `SamlError::Xml`, as XML 1.0 and Namespaces in XML
require of a parser:

- an element still open at the end of the input, such as `<Root/><Second>`,
  including in `parse_roots`;
- `<` in an attribute value;
- a character outside the XML character range, written directly or as a
  character reference: a control character other than tab, line feed, and
  carriage return, U+FFFE, or U+FFFF;
- `--` inside a comment;
- a namespace prefix that the document does not declare;
- a binding of the `xmlns` prefix, a binding of `xml` to another namespace, or
  another prefix or the default namespace bound to the `xml` or `xmlns`
  namespace;
- two attributes on one element with the same namespace and local name;
- `]]>` in text;
- two attributes with no whitespace between them, such as `x="1"y="2"`;
- an element or attribute name that is not a qualified name: not an XML name,
  such as `1a`, with more than one colon, such as `a:b:c`, or with an empty
  prefix or local part, such as `a:`;
- an XML declaration that is not at the very start of the input, or a
  processing instruction whose target is `xml` in any letter case;
- an empty namespace name for a prefix, such as `xmlns:p=""`. An empty default
  namespace, `xmlns=""`, is still accepted.

A namespace name is compared after its character and entity references are
resolved, so `xmlns:b="&#x75;rn:a"` binds `urn:a`.

**Changed error variants:**

| Input | Before | Now |
| --- | --- | --- |
| Received message whose root, or a SAML element such as `<Assertion>`, uses an undeclared prefix | `SamlError::ProtocolProfile` | `SamlError::Xml`, before protocol-profile validation |
| More namespace bindings in scope than `XmlLimits::max_attributes_per_element` (64 by default) | `SamlError::Xml` from protocol-profile validation for messages; no limit for metadata | `SamlError::Invalid` with `ERR_XML_LIMIT_EXCEEDED` |

Update a `match` that expected the old variant. Raise
`max_attributes_per_element` if a metadata document you trust declares more.

`saml_rs::xml::extract` and `extract_with_limits` still accept one element cut
out of a larger document, such as an extracted `context` value, whose
prefixes are declared on an ancestor outside it. The other checks apply to it.

**Upgrade:** no option accepts the rejected input. Ask the peer to fix the XML
it sends.

## 7.2 Expect a line feed for each line break in received text

**Affects:** text that `saml-rs` reads from parsed XML: a `NameID`, an
attribute value, an `Issuer`, and every other element value in received
messages and metadata, including `saml_rs::xml::dom` and
`saml_rs::xml::extract` results.

**Before:** the carriage return was kept, so a peer that writes line breaks as
CRLF produced `"alice\r\nx"` where the signed value is `"alice\nx"`.
**Now:** a carriage return followed by a line feed, or a carriage return on its
own, written literally in text or in a CDATA section, reaches you as one line
feed, as XML 1.0 §2.11 requires. A carriage return written as `&#xD;` is still
a carriage return. XML attribute values, such as `Destination`, already worked
this way.

**Upgrade:** if you stored values received before the upgrade and compare them
with new ones, convert the stored values from peers that write literal line
breaks:

```rust
let stored = stored.replace("\r\n", "\n").replace('\r', "\n");
```

A value whose peer wrote the carriage return as `&#xD;` keeps it after the
upgrade, so do not convert those.

## 7.3 Size `XmlPolicy::limits` for SOAP envelopes and SimpleSign messages

**Affects:** deployments that set `XmlPolicy::limits` on the `Saml` instance
and receive SOAP through `answer_artifact_resolve`,
`ArtifactResolution::finish`, `receive_slo` or `finish_slo` with
`BrowserInput::soap`, `receive_name_id_management`, or
`StartedNameIdManagement::finish`, or receive HTTP-POST-SimpleSign messages.

**Before:** these inputs were read under `XmlLimits::default()`.
**Now:** the whole SOAP envelope, header included, and the decoded
SimpleSign message are read under the configured limits. A SOAP envelope over
a configured limit returns `SamlError::Invalid` with `ERR_XML_LIMIT_EXCEEDED`.
A SimpleSign message whose decoded size is over `max_bytes` returns
`SamlError::Invalid` with `ERR_BASE64_OUTPUT_LIMIT_EXCEEDED`. A limit above
the default now admits a larger input.

**Upgrade:** if you set limits below the defaults, check that they still fit
the largest envelope or SimpleSign message your peers send.
`SoapProtocolMessage::from_envelope` and the `TryFrom<BrowserInput>`
conversions to `HttpRequest` have no configuration and keep the defaults.

## 7.4 Send one SOAP `Header` before the `Body`

**Affects:** the calls in [section 7.3](#73-size-xmlpolicylimits-for-soap-envelopes-and-simplesign-messages)
that read SOAP, and `SoapProtocolMessage::from_envelope`. See
[SOAP envelope rules](../../conformance/artifact-resolution.md).

**Now:** the SOAP envelope reader returns `SamlError::ProtocolProfile` when a
`Header` follows the `Body` or the envelope has more than one `Header`. An
envelope with two `Body` elements, one of them empty, returns
`SamlError::ProtocolProfile` instead of `SamlError::Xml`. The ECP reader
already refused these envelopes. SOAP 1.1 §4 requires a `Header` to be the
first child of `Envelope` and the `Body` to follow it.

**Upgrade:** ask a peer that sends another order to send a SOAP 1.1 envelope.

## 7.5 Expect signatures in SOAP messages to be verified where they sit

**Affects:** SAML messages received over SOAP: `receive_slo` and `finish_slo`,
`receive_name_id_management` and `StartedNameIdManagement::finish`,
`answer_artifact_resolve` and `ArtifactResolution::finish`, and
`receive_paos_sso`, `finish_paos_sso`, and
`finish_paos_sso_with_outstanding_logout`.

**Now:** the message read from a SOAP body declares every namespace in scope
from its ancestors, including the envelope's, and its signature is verified
against that element. Inclusive Canonical XML (`REC-xml-c14n-20010315`) takes
those declarations into the digest, so a verifier computes it as it would on
the message in place in the envelope.

| Message signed by the peer | Before | Now |
| --- | --- | --- |
| Alone, with exclusive canonicalization and no `InclusiveNamespaces` `PrefixList` naming an envelope prefix (saml-rs and most peers) | Accepted | Accepted |
| Alone, with Canonical XML, then wrapped in SOAP | Accepted | `SignatureVerification` with `SignatureVerificationReason::XmlSignature` |
| Alone, with exclusive canonicalization and a `PrefixList` naming a prefix the envelope declares | Accepted | `SignatureVerification` with `SignatureVerificationReason::XmlSignature` |
| With Canonical XML in place in the envelope | Rejected | Accepted |

The strings returned by `SoapProtocolMessage::xml()` and
`ResolvedProtocolMessage::xml()`, and a decrypted assertion, now carry these
inherited `xmlns` declarations, such as `xmlns:soap` from the envelope or the
`Response` namespaces on an assertion. Parse them as XML rather than comparing
them as text.

**Upgrade:** ask a peer that signs a standalone message with Canonical XML to
sign with exclusive canonicalization, as SAML Core §5.4.3 and §5.4.4
recommend, or to sign the message in place in the envelope.

## 7.6 Handle refused SOAP headers on PAOS logins

**Affects:** `receive_paos_sso`, `finish_paos_sso`, and
`finish_paos_sso_with_outstanding_logout`. See
[Enhanced Client/Proxy SSO](../../conformance/enhanced-client-proxy.md).

| Envelope | Before | Now |
| --- | --- | --- |
| A header entry with `mustUnderstand="1"` or `"true"` that the receiver does not process | Ignored | `SamlError::Xml` |
| Not SOAP 1.1, a `Header` or `Body` outside the SOAP namespace, an `Envelope` child other than `Header` and `Body`, a missing `Body`, or an empty `Body` | `SamlError::ProtocolProfile` | `SamlError::Xml`, as the other SOAP readers already returned |

The service provider still accepts `ecp:RelayState` and `paos:Response`. The
identity provider accepts no `mustUnderstand` entry. `paos_soap_fault` answers
the identity provider error with a SOAP `Client` fault, as for any envelope
that is not a SAML request.

**Upgrade:** an enhanced client that sends such an entry must stop marking it
`mustUnderstand` or leave it out. If you branch on the variant, match both.

## 7.7 Remove Unicode whitespace before `base64_decode`

**Affects:** callers that pass base64 to `saml_rs::binding::base64_decode` or
`saml_rs::crypto::verify_message_signature`, and HTTP-Redirect and
HTTP-POST-SimpleSign reception of a `Signature` value.

**Before:** `base64_decode` skipped every Unicode whitespace character.
**Now:** it ignores the same whitespace as `base64_decode_with_limit`: space,
tab, line feed, form feed, and carriage return. Vertical tab, no-break space,
line separator, ideographic space, and every other Unicode whitespace character
return `SamlError::Base64`. Line-wrapped base64 still decodes.

**Upgrade:** if an integration must accept that input, remove the characters
before decoding:

```rust
let cleaned: String = input.split_whitespace().collect();
let bytes = saml_rs::binding::base64_decode(&cleaned)?;
```

## 7.8 Accept a received RelayState longer than 80 bytes

**Affects:** typed reception through `receive_sso`, `finish_sso`,
`accept_unsolicited_sso`, `receive_slo`, `finish_slo`,
`receive_name_id_management_redirect`, `finish_name_id_management_redirect`,
or `DeliveredArtifact::from_query` and `from_form`, and code that stores a
received RelayState. See
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md),
[HTTP-Artifact](../../conformance/web-browser-sso-artifact.md),
[Single Logout rules](../../conformance/single-logout.md), and
[name identifier management](../../conformance/name-id-management.md).

**Before:** a received RelayState longer than 80 bytes returned
`SamlError::Invalid`, and responders could not echo one.
**Now:** it is accepted up to `MAX_RECEIVED_RELAY_STATE_BYTES` (4096 bytes).
Bindings §3.4.3, §3.5.3, and §3.6.3.1 limit the value the sender creates, not
what a receiver accepts. A longer value still returns `SamlError::Invalid`.
`respond_sso`, `respond_sso_artifact`, `respond_slo`, and
`respond_name_id_management_redirect` return a long received RelayState
unchanged, as Bindings §3.4.3 and §3.5.3 require.

A RelayState you create is still limited to 80 bytes. Passing a received long
value to `StartSso::relay_state`, `StartSlo::relay_state`,
`StartNameIdManagement::relay_state`, or `RespondSso::relay_state` returns
`SamlError::Invalid`. To answer a request with its own RelayState, leave
`RespondSso::relay_state` unset.

**Upgrade:** code that assumes every `RelayState` or `RelayStateParam` is at
most `MAX_RELAY_STATE_BYTES` must change. Check the length before you store a
received value in a column or cookie sized for 80 bytes.

## 7.9 Send one RelayState per message

**Affects:** typed reception over HTTP-POST or HTTP-Redirect with
`receive_sso`, `finish_sso`, `accept_unsolicited_sso`, `receive_slo`,
`finish_slo`, `receive_name_id_management_redirect`, or
`finish_name_id_management_redirect`. See
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md),
[Single Logout rules](../../conformance/single-logout.md), and
[name identifier management](../../conformance/name-id-management.md).

**Before:** HTTP-POST and unsigned HTTP-Redirect used the first value and
ignored the others. An HTTP-Redirect query that repeated the exact name
`RelayState` returned `SamlError::Invalid("ambiguous Redirect field RelayState")`.
**Now:** a second `RelayState` form field or query parameter returns
`SamlError::Invalid("ambiguous form field")`. Names are compared after URL
decoding, so `RelayState=a&Rel%61yState=b` is a repeat. A repeated
`RelayState` was already refused on HTTP-POST-SimpleSign, on a signed
HTTP-Redirect, and on HTTP-Artifact. Bindings §3.4.3 and §3.5.3 define one
`RelayState` per message, so a conformant peer is not affected.

**Upgrade:** fix a peer or a proxy that adds a second `RelayState`, or remove
the extra field before you build the `BrowserInput`.

## 7.10 Keep encrypted messages within the decryption work limit

**Affects:** every inbound encrypted-element operation with a decryption key,
including raw assertion decryption, typed SSO, requested subjects, logout, and
name identifier management.

**Before:** XML byte limits allowed large lists of key candidates, retried for
each configured rollover key before content authentication.
**Now:** the default allowance is `constants::DEFAULT_MAX_DECRYPTION_WORK`
(16). Set it with `XmlEncryptionPolicy::with_max_decryption_work`. Each `xenc:EncryptedData`,
`xenc:EncryptedKey`, and `xenc11:DerivedKey` in the input costs one unit per
configured decryption key, including `additional_decryption_keys`. The
document is checked before decryption. Newly revealed encrypted elements are
added to that allowance before any subsequent decryption. This conservative
count includes unused candidates and allows one retrieval attempt per data
element. One ordinary encrypted element with one wrapped key costs two units.

Excess work returns `SamlError::Invalid` containing
`ERR_DECRYPTION_LIMIT_EXCEEDED`. Name identifier management reports that error
through its existing decryption-refusal result. Parser limits, a valid
signature, and the CBC or RSA-v1.5 opt-ins do not relax this resource limit.
This is library resource policy, not an OASIS receiver obligation.

The count is a conservative estimate per message, not a CPU timer, an actual
operation counter, or a request-rate limit:

```text
(EncryptedData + EncryptedKey + DerivedKey) × configured local keys
```

One ordinary encrypted element with one wrapped key and two local rollover
keys costs four units. Four such elements cost 16; five cost 20. The latter
requires a higher configured allowance. Unused candidates still count even
if the first key would succeed. Sixteen is a library default chosen to bound
work, not a threshold prescribed by SAML or a guaranteed processing time.

**Upgrade:** size the allowance for your encrypted elements, recipient keys,
and local rollover keys. For example:

```rust
use saml_rs::{XmlEncryptionPolicy, XmlPolicy};

let xml = XmlPolicy {
	encryption: XmlEncryptionPolicy::encrypt_assertions().with_max_decryption_work(64),
	..XmlPolicy::default()
};
```

Raw integrations set `EntitySetting::max_decryption_work` or
`FlowOptions::max_decryption_work`. Direct decryption sets
`AssertionDecryptionOptions::max_decryption_work`. Zero refuses encrypted
input; there is no separate unlimited mode. Signed and unsigned GCM Responses
remain supported within the selected allowance. Request-rate and concurrency
limits belong to the hosting application.

## 7.11 Check XML signature references and coverage

**Affects:** callers of `crypto::verify_signature`,
`crypto::verify_signature_with_limits`, `BergshamraBackend`, metadata signature
verification helpers, and flows that verify embedded XML signatures.

#### Keep processed references within the document

Every signature passed to the cryptographic verifier now takes the existing
same-document reference checks, including signatures inside extensions.
Previously, these checks covered only signatures directly under the root or
its direct Assertion children. All-signatures flows reject a processed external
reference with `SamlError::ReferenceResolution`, with reason
`ReferenceResolutionReason::ExternalReference`, before resolving references or
running transforms. Unsupported fragment forms keep
`ReferenceResolutionReason::UnsupportedReferenceUri`.

If your peer includes optional signatures with external references, remove
those signatures or change them to reference content within the message.
`AllowProviderSupportedForCompatibility` does not allow external references.
With `StrictRsaSha2`, every processed signature must also use only the existing
allowed reference transforms, even when that signature would fail verification
or cover unrelated content. Replace other transforms with enveloped-signature
and exclusive canonicalization transforms, or remove the optional signature.
The failure is `SamlError::AlgorithmUnsupported`.

The public `verify_signature` functions still process the first XML-DSig
signature in document order when a SAML candidate signature is present. They
preflight that actual first signature. They do not process later signatures.
Flows that inspect all signatures preflight all of them. Harmless optional
signatures that fail verification outside SAML candidate positions remain
ignorable when their processing passes these restrictions.

#### Consume the returned signed content

A successful public verification now always returns `(true, Some(xml))`.
For an assertion-bearing protocol response, `xml` remains the consumed signed
Assertion, and the existing checks still require coverage of every direct
Assertion. Other documents require coverage of the document root and return
that root. This includes status-only Responses, ArtifactResolve,
ManageNameIDRequest, and ArtifactResponse documents.

If you relied on `(true, None)`, handle `SamlError::SignedReferenceMismatch`
when a valid signature covers only a different object. Have the peer sign the
root of the document you need to authenticate. Root-covered documents that
previously returned no content now return their signed root.
`BergshamraBackend` applies the same guarantee before returning `Ok(())`.
Assertion-only signatures on SSO Response containers remain supported.

Flows that verify embedded signatures apply the same root-coverage rule.
Error and status-only Responses signed over another element now fail with
`SamlError::SignedReferenceMismatch` instead of reaching status handling.
For malformed successful Responses without Assertions, allow issuer-validation
errors as well as the previous empty-Assertion error when matching flow errors.

#### Verify metadata roots with metadata helpers

`crypto::verify_metadata_signature*` and `Metadata::verify_signature*` now
succeed only for a covered `EntityDescriptor` or `EntitiesDescriptor` root.
Previously, these helpers also accepted some signed non-metadata messages,
including LogoutRequest. Passing those roots now returns
`SamlError::SignedReferenceMismatch`. Pass a metadata descriptor to these
helpers. Use `crypto::verify_signature` for other signed XML documents.

These are library processing and coverage guarantees. They do not add general
schema or protocol validation to the public verification functions. The exact
standards scope and library policies are recorded in
[XML signature processing](../../conformance/xml-security-algorithms.md#reference-and-coverage-processing).
