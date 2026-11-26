# Rename the signature and replay policies

[How to upgrade from 0.8 to 0.9](README.md)

Update code that reads or assigns these policy fields. The service provider
chooses whether to sign the AuthnRequests it sends. The identity provider
chooses which signatures it requires on the AuthnRequests it receives.

| 0.8 field | 0.9 field |
| --- | --- |
| `SpValidationPolicy::authn_requests` | `SpValidationPolicy::authn_request_signing` |
| `IdpValidationPolicy::authn_requests` | `IdpValidationPolicy::authn_request_signatures` |
| `SpValidationPolicy::assertions` | `SpValidationPolicy::assertion_signatures` |
| `SpValidationPolicy::responses` | `SpValidationPolicy::response_signatures` |

Check the [variant rename table](compile-errors.md#116-rename-the-relaxed-policy-and-algorithm-variants)
for the policy values you assign. To sign all outbound AuthnRequests and
require signatures on all inbound AuthnRequests, configure both roles as
follows.

```rust
use saml_rs::{
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, IdpValidationPolicy,
    SpValidationPolicy,
};

let mut sp_validation = SpValidationPolicy::default();
sp_validation.authn_request_signing = AuthnRequestSigningPolicy::Sign;

let mut idp_validation = IdpValidationPolicy::default();
idp_validation.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
```

Replace `ReplayPolicy::DisabledForCompatibility` with `ReplayPolicy::NoCache`
in values, imports, and match patterns. `NoCache` skips optional replay
checks. HTTP-POST SSO acceptance requires `ReplayPolicy::RequireCache` and
returns `SamlError::ReplayCacheRequired` without a cache.

Update any snapshots of `Debug` output that include the old field or variant
names.
