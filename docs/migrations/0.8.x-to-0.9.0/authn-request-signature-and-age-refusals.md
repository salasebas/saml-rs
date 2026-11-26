# Answer AuthnRequests refused for their signature or age

`IdentityProvider::receive_sso` now returns `SamlError::AuthnRequestRefused`
for two more requests:

- An unsigned request when the identity provider requires signed requests
  with `AuthnRequestValidationPolicy::RequireSigned`. Before, it returned
  `SamlError::SignatureMissing`.
- A request whose `IssueInstant` is outside the window set with
  `SamlValidationContext::with_authn_request_age`. Before, it returned
  `SamlError::TimeWindowInvalid` with `TimeWindowField::AuthnRequestIssueInstant`.

For these two requests, the new `RefusedAuthnRequest::reason` returns an
`AuthnRequestRefusalReason`: `Unsigned` or `OutsideAgeWindow`. An unsigned
request from a service provider whose metadata sets `AuthnRequestsSigned`
still returns the refusal, now with `Unsigned` as its reason. When a request is both unsigned and too old, the
reason is `Unsigned`.

SAML Profiles §4.1.4.1 requires an identity provider that will not satisfy a
request to answer with an error `Response`. The refusal carries the request
and its RelayState, so `respond_sso_refusal` and
`respond_sso_refusal_artifact` can send that response to a trusted assertion
consumer service.

This change affects an identity provider login handler that matches
`SignatureMissing` or `TimeWindowInvalid` from `receive_sso`. No code fails
to compile. Match `AuthnRequestRefused` before the other errors and send the
refusal. Show a local error page only when `respond_sso_refusal` fails because
no trusted assertion consumer service can receive the response:

```rust
match idp.receive_sso(&sp, input, validation) {
    Err(SamlError::AuthnRequestRefused { refusal, .. }) => {
        let response = idp.respond_sso_refusal(&sp, &refusal, RespondSso::post())?;
        // Send response.post_form()? to the browser.
    }
    Ok(request) => {
        // Authenticate the user.
    }
    Err(error) => return Err(error),
}
```

A present `Destination` that does not match the receiving endpoint still
returns `SamlError::DestinationMismatch` and no refusal.
