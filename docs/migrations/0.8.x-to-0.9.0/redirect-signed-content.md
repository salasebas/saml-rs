# Send AuthnRequests with signed extension content over HTTP-POST

This change affects a service provider that sends an `AuthnRequest` over
HTTP-Redirect with extension content that holds an XML signature. No code
fails to compile.

`ServiceProvider::start_sso` with `StartSso::redirect()` now returns
`SamlError::SignedContentOnRedirect` when an element passed to
`StartSso::extension` holds a `ds:Signature` at any depth. HTTP-POST and
HTTP-POST-SimpleSign carry the element unchanged, as before.

In 0.8, `TemplatePolicy::login_request_template` could hold any XML, and
`start_sso` deflated a signed element of the template into the redirect query.
[Replace SSO templates with typed options](config.md#replace-sso-templates-with-typed-options)
moves that content to `StartSso::extension`.

Bindings §3.4.4.1 says that a message with signed content should not be
encoded with HTTP-Redirect. The encoding removes only the message's own
signature, and an embedded signature makes the URL too long for the binding.

To upgrade, send such a request with `StartSso::post()`:

```rust
use saml_rs::{ExtensionElement, StartSso};

let extension = ExtensionElement::from_xml(signed_element_xml)?;
let options = StartSso::post().extension(extension);
```

No option sends the request over HTTP-Redirect. `SamlError` is
`#[non_exhaustive]`, so a `match` on it already has a wildcard arm. Add a
`SignedContentOnRedirect` arm if you handle the refusal apart from other
errors.
