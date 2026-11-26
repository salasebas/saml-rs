# Repeat unsigned and refused requests without a replay error

With `ReplayPolicy::RequireCache`, two receive operations now store fewer
request IDs in the replay cache:

- `IdentityProvider::receive_sso` stores the `ID` of an authenticated
  `AuthnRequest` only. An unsigned request that the identity provider
  accepts is no longer stored. Repeating it returns the request again instead
  of `SamlError::ReplayDetected`.
- `receive_name_id_management_redirect`, on both roles, no longer stores the
  `ID` of a request it refuses with `NameIdManagementRefusal::VersionMismatch`.
  Repeating it returns the same refusal instead of `SamlError::ReplayDetected`.
  The SOAP operation and `receive_slo` already behaved this way.

An unsigned request `ID` stops no replay, because anyone can send the same
request with a new `ID`. Storing it only let unauthenticated senders fill the
cache. A refused request changes no state, and its repeat gets the answer the
requester needs.

The change affects an identity provider that accepts unsigned AuthnRequests
and passes a cache, and a provider that receives newer-version name
identifier management requests over HTTP-Redirect. No code fails to compile.
An unsigned AuthnRequest no longer needs `with_replay_retention`, so it no
longer returns `SamlError::TimeWindowInvalid` when the retention is missing.

To refuse unsigned AuthnRequests, require signed requests:

```rust
use saml_rs::{AuthnRequestValidationPolicy, IdpValidationPolicy};

let mut validation = IdpValidationPolicy::default();
validation.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
```

Pass `validation` to `IdpConfig::builder(..).validation(..)` as before.
