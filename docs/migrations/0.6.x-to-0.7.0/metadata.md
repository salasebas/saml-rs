# Correct metadata and endpoint selection

[How to upgrade from 0.6 to 0.7](README.md)

## Check keys, roles, and signing flags

If metadata contains both SP and IdP roles, publish each role's keys and
logout endpoints inside its own descriptor. `SpMetadata` and `IdpMetadata`
now use only their respective roles, including through typed descriptors
and raw providers. Missing keys or endpoints in that role no longer fall
back to the other role. Generic `Metadata::parse` remains role-independent.
A message signed with a key that only the other role publishes fails, usually
with `SamlError::CertificateMismatch`. Encrypting for a role that publishes no
encryption certificate returns `SamlError::MissingMetadata`, even when the
other role publishes one. A raw `IdentityProvider` writes `SessionIndex` only
when its `IDPSSODescriptor` publishes a `SingleLogoutService`.

Correct each key's `KeyDescriptor` `use`. A signing-only key no longer
encrypts, and an encryption-only key no longer verifies signatures, even
when it is the only key. Omit `use` for a key serving both purposes.
Keys without `use` now participate alongside explicitly scoped keys.
When a peer's only key has the other `use`, its XML signatures fail with
`SamlError::NoTrustedCertificate`, its HTTP-Redirect and HTTP-POST-SimpleSign
signatures with `SamlError::SignatureVerification`, and encryption to it with
`SamlError::MissingMetadata`.

If metadata uses `1`, `0`, or surrounding whitespace for signing flags,
check the intended values. `1` now means true. Sign AuthnRequests when
`AuthnRequestsSigned` requires it, reject unsigned requests when
`WantAuthnRequestsSigned` requires it, and require signed assertions when
`WantAssertionsSigned` requires it. Publish `false` where unintended.
`start_sso` returns `ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG` when one side
of the SP and IdP metadata is now true and the other is false.

If you compare generated metadata byte for byte or read children by position,
update the expected schema order:

```text
SP before:  KeyDescriptor, NameIDFormat, SingleLogoutService, AssertionConsumerService
SP after:   KeyDescriptor, SingleLogoutService, NameIDFormat, AssertionConsumerService
IdP before: KeyDescriptor, NameIDFormat, ArtifactResolutionService, SingleSignOnService, SingleLogoutService
IdP after:  KeyDescriptor, ArtifactResolutionService, SingleLogoutService, ManageNameIDService, NameIDFormat, SingleSignOnService
```

Prefer updating comparisons over retaining an old order that schema-validating
peers reject. To keep the old service provider order, pass
`elements_order::ONELOGIN` to `elements_order`. For the old identity provider
order, pass the old list above. See
[metadata rules](../../conformance/metadata-and-replay.md).

## Select the actual receiving URL

If you publish several receiving URLs for one binding, set the handler's
externally visible URL before `Saml<Idp>::receive_sso`, `receive_slo`, or `finish_slo`:

```rust
let validation = validation.with_recipient_endpoint(
	EndpointUrl::try_new("https://idp.example.com/sso/second")?,
);
```

Take the URL from trusted handler configuration or HTTP request context.
Use `SingleSignOnService` `Location` for SSO, `SingleLogoutService` `Location`
for logout requests, and `ResponseLocation` for logout responses, falling
back to `Location` when absent. Ambiguous or unpublished receiving URLs
return `SamlError::Invalid`. Messages for another URL return
`SamlError::DestinationMismatch`, even if that URL is also published.

If your IdP uses `AuthnRequestValidationPolicy::RequireSigned`, ensure peers
include `Destination`, set to your `SingleSignOnService` URL, on signed
Redirect, POST, and SimpleSign AuthnRequests.
Missing values now return `SamlError::DestinationMismatch`.
`saml-rs` SPs already send it. PAOS reception is unchanged.

## Check the default ACS and binding

If login relied on the first ACS, mark the intended default with
`AcsEndpoint::mark_default` or update metadata. `respond_sso` without an
explicit ACS or binding, and `initiate_sso`, now use the SP role's default ACS.
Match its binding with `RespondSso::post` or `RespondSso::simple_sign`.
A mismatch or unsupported default returns `SamlError::Invalid`.

Binding-only requests, `start_sso`, and raw lookups choose the default within
the binding's candidates. Explicit ACS URLs and indexes retain their selection.
For PAOS, set `StartPaosSso::acs_url` if the new default selects another endpoint.
