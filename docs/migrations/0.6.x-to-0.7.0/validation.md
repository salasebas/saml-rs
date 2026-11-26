# Replace removed policies and check defaults

[How to upgrade from 0.6 to 0.7](README.md)

Replace `SpValidationPolicy::strict()`, `IdpValidationPolicy::strict()`, and
`LogoutPolicy::strict()` with `recommended()`. Set additional checks explicitly.
For an SP that requires signed assertions, signs AuthnRequests, and requires
an audience restriction:

```rust
let policy = SpValidationPolicy {
	assertions: AssertionSignaturePolicy::RequireSigned,
	authn_requests: AuthnRequestSigningPolicy::Sign,
	audience: AudienceValidationPolicy::Validate,
	..SpValidationPolicy::recommended()
};
```

To require the RSA-SHA2 XML-DSig profile too, set
`xml_signatures: XmlSignatureProfile::StrictRsaSha2`.
For an IdP that rejects unsigned AuthnRequests, set
`IdpValidationPolicy::authn_requests` to `AuthnRequestValidationPolicy::RequireSigned`.
`LogoutPolicy::recommended()` still requires signed requests and responses.

Check code that relies on constructor defaults. Policy `default()` and
`SpConfig` and `IdpConfig` `new`, `try_new`, and `builder` now use Recommended.
It allows unsigned AuthnRequests and bearer assertions without audience
restrictions. It makes AuthnRequest signing and direct Assertion signatures
optional. Use the fields above to require those checks.

To retain the legacy permissive policy, select `compatibility()` explicitly.
Without a crypto provider, select it or another policy that does not require
signatures. Otherwise `try_new` and `builder().build()` return
`SamlError::Unsupported`. `new` does not validate.
Raw settings and individual field defaults are unchanged.
See [validation presets](https://samlrs.vercel.app/explanation/validation-presets/) for policy details.
