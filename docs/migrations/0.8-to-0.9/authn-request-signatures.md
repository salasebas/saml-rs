# Update AuthnRequest signature verification

[How to upgrade from 0.8 to 0.9](README.md)

When upgrading from 0.8, replace `AllowUnsignedVerifyIfPresent` or
`AllowUnsignedForCompatibility` with `AuthnRequestValidationPolicy::AllowUnsigned`.
If you used `AllowUnsignedForCompatibility`, or `AllowUnsigned` from an
unreleased revision, the IdP now verifies present signatures and enforces
`AuthnRequestsSigned` in SP metadata. Callers using `IdpValidationPolicy::default()`
need no code changes.

```diff
-validation.authn_requests = AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent;
+validation.authn_requests = AuthnRequestValidationPolicy::AllowUnsigned;
```

For browser SSO, publish each signing key in the SP metadata you
give the IdP. The IdP verifies every signature on the request, including an
XML signature carried alongside a detached signature. A request with a
signature that fails verification is rejected.

The default accepts unsigned requests from an SP that permits them in its
metadata. If the SP advertises `AuthnRequestsSigned="true"`, it must sign
its requests. To require signatures from every SP, keep using `RequireSigned`.
