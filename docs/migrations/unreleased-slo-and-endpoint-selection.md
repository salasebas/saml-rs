# How to update endpoint routing and logout responses

This change is unreleased. Existing calls compile, but endpoint routing and
some error cases change. Check the sections that apply to your integration.

## Set the actual receiving URL

If you publish several distinct receiving URLs for the incoming binding,
add the handler's externally visible URL to the validation context before
calling `Saml<Idp>::receive_sso`, `receive_slo`, or `finish_slo`:

```rust
use saml_rs::EndpointUrl;

let validation = validation.with_recipient_endpoint(
	EndpointUrl::try_new("https://idp.example.com/sso/second")?,
);
```

Use trusted handler configuration or trusted HTTP request context. Do not
copy the message's `Destination`. With one published URL, the existing calls
can infer the endpoint.

The receiving URL must be published for the binding and message direction:

| Method | Published receiving URL |
| --- | --- |
| `receive_sso` | `SingleSignOnService` `Location` |
| `receive_slo` | `SingleLogoutService` `Location` |
| `finish_slo` | `SingleLogoutService` `ResponseLocation`, or `Location` when absent |

Ambiguous selection or an unpublished receiving URL returns
`SamlError::Invalid`. A message for another URL returns
`SamlError::DestinationMismatch`, even if that URL is also published.

## Check your default ACS and response binding

When a request specifies no ACS URL, ACS index, or `ProtocolBinding`,
`respond_sso` uses the default Assertion Consumer Service (ACS) in the
SAML 2.0 SP role. `initiate_sso` uses that default too.

If you relied on another endpoint, mark the intended default with
`AcsEndpoint::mark_default` or update your metadata. Choose
`RespondSso::post` or `RespondSso::simple_sign` to match its binding.
An unsupported default or a binding mismatch returns `SamlError::Invalid`.

Explicit ACS URLs and indexes keep their selection. Binding-only requests,
`start_sso`, and raw lookups now choose the default within their binding's
candidates, rather than the first endpoint. Update your defaults if you
relied on that first endpoint for raw generation or response parsing.

`start_paos_sso` applies the default rule to POST and SimpleSign candidates.
If that changes your endpoint, set `StartPaosSso::acs_url` explicitly or
update the metadata default.

## Receive logout responses at ResponseLocation

If a peer publishes a non-empty `ResponseLocation`, logout responses now go
there. Accept responses at that URL, or omit the attribute to use `Location`
for both messages. Logout requests still go to `Location`.

If the SP applies logout generation rules, use an HTTPS response URL or
explicitly select `RespondSlo::allow_http_single_logout`.

## Reply through the matching peer descriptor

Pass the descriptor whose entity ID matches the `LogoutRequest` issuer to
`respond_slo`. Both roles now return `SamlError::IssuerMismatch` if you pass
a descriptor for another party.

The exact rules and normative sources are in the reference pages for
[SSO generation](../conformance/web-browser-sso-generation.md),
[SSO acceptance](../conformance/web-browser-sso-acceptance.md), and
[Single Logout](../conformance/single-logout.md).
