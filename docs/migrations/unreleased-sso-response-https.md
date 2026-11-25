# Send SSO responses to an `http` ACS only under `allow_http`

If you run an identity provider, `IdentityProvider::respond_sso`,
`respond_sso_refusal`, `initiate_sso`, and their artifact variants now
return `SamlError::ProtocolProfile` when the selected
`AssertionConsumerService` `Location` is not `https`. Before, the identity
provider sent the user agent to an `http` location, so the browser carried
the assertion or the artifact without TLS.

Web Browser SSO recommends TLS for the request that delivers the response to
the service provider. The crate already applies the same rule to Single
Logout and name identifier management.

If a service provider publishes only an `http` assertion consumer service,
for example on a development host, select `RespondSso::allow_http`:

```rust
let response = idp.respond_sso(sp, &request, assertion, RespondSso::post().allow_http())?;
```

A service provider whose selected assertion consumer service is `https` is
answered as before. The check applies to the location chosen by the request
or by the metadata default, and does not pick another endpoint.
