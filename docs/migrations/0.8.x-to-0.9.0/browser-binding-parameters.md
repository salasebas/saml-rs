# Handle browser binding parameter errors

These changes affect deployments that send `RelayState` in a form, that
configure Redirect endpoints with a query string, or that receive HTTP-Redirect
messages from peers.

## RelayState in a form

An operation that puts `RelayState` in a POST form, a SimpleSign form, or an
artifact form returns the new `SamlError::RelayStateNotRepresentable` in two
cases. Its `binding` field names the form's binding.

- The value has a CR or LF outside a CRLF pair. HTML form submission sends
  such a character as CRLF.
- The value has a character that XML cannot represent, such as U+0000. The
  bindings require an XHTML form, and an HTML parser reads U+0000 as U+FFFD.

In both cases the receiver would get a different value, and a SimpleSign
signature over the original value would fail. Before the upgrade, the
operation built the form.

Every operation that sends a form can return the error, for example
`ServiceProvider::start_sso` with `StartSso::post()` and
`IdentityProvider::respond_sso` with `RespondSso::post()`. A responder that
received `RelayState=line%0Abreak` or `RelayState=a%00b` over HTTP-Redirect
cannot return it in a form.

If your application stores multi-line text or control characters in
`RelayState`, encode the value before you build the `RelayState` whenever the
request or the response uses a form. A request sent over HTTP-Redirect still
fails when the responder answers with a form. A responder must return the
received value exactly. It can answer only over another delivery the exchange
permits, such as an HTTP-Redirect `LogoutResponse` or an artifact URL. A CRLF pair and a tab are still
accepted. When you render the form, escape tab, CR, and LF as character
references.

## SAML parameters in a Redirect endpoint query

An operation that builds a Redirect URL or an artifact URL returns
`SamlError::Invalid` when the endpoint query already has `SAMLRequest`,
`SAMLResponse`, `SAMLart`, `RelayState`, `SigAlg`, `Signature`, or
`SAMLEncoding`. Names match after percent-decoding, so `Relay%53tate` counts.
Leading `?` characters of the query are skipped, as `Inbound::redirect` skips
them, so `/sso??RelayState=x` also counts. To send a parameter literally named
`?RelayState`, encode the question mark: `/sso?%3FRelayState=x`.
Before the upgrade, a protocol message Redirect kept a configured
`RelayState`, `SigAlg`, `Signature`, `SAMLart`, or `SAMLEncoding` in the URL.
A configured copy of the message's own field, such as `SAMLRequest` on a
request, returned `SamlError::DuplicateBindingParameter`, and the other message
field returned `SamlError::Invalid`. An artifact URL kept every configured
parameter, so a configured `SAMLart` produced two `SAMLart` fields.

The endpoint comes from your configuration or from peer metadata. Remove the
SAML parameter from that endpoint `Location`. Other query parameters stay in
the URL before the SAML parameters.

## Received query parameters

The operations that receive an `Inbound::redirect` message read
`SAMLRequest`, `SAMLResponse`, `RelayState`, `SigAlg`, `Signature`, and
`SAMLEncoding` by their decoded names. `DeliveredArtifact::from_query` reads
`SAMLart` and `RelayState` the same way. Each ignores other parameters. A
signed message whose sender percent-encodes a parameter name now verifies.

Both return `SamlError::Invalid` when a parameter they read is not UTF-8 after
percent-decoding. Before the upgrade, `RelayState=caf%E9` became
`caf\u{FFFD}`, so the response returned a different value. If a peer sends
`RelayState` in another character encoding, ask it to send UTF-8.

The `Inbound::redirect` operations return `SamlError::Unsupported` when
`SAMLEncoding` is present and is not
`urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE`, including an
empty value. Before the upgrade, the message was inflated as DEFLATE. A
repeated `SAMLEncoding` returns `SamlError::DuplicateBindingParameter`. These
operations read `SAMLEncoding` before the other parameters, so an unsupported
encoding is reported before a non-UTF-8 `SAMLRequest`.
