# Send SAML errors when an SP omits a required request signature

[How to upgrade from 0.8 to 0.9](README.md)

When an SP declares `AuthnRequestsSigned` but sends an unsigned browser
`AuthnRequest`, `IdentityProvider::receive_sso` returns
`SamlError::AuthnRequestRefused` in place of `SignatureMissing` for an
otherwise valid request.

If your IdP login handler catches `SignatureMissing` or sends a local error
page for every receipt error, match `AuthnRequestRefused` first.
Pass its `refusal` and the same SP descriptor to
`IdentityProvider::respond_sso_refusal` for HTTP-POST or SimpleSign.
For HTTP-Artifact, call `IdentityProvider::respond_sso_refusal_artifact` with
your artifact delivery options and store.

Send the returned `Outbound<SsoResponse>` to the browser. It carries a
`Requester` status, the original request ID as `InResponseTo`, and any
received RelayState. If response creation fails, handle the error locally.

If an otherwise acceptable request names an ACS index that current SP metadata
no longer contains, issuing success still returns `MissingMetadata`.
To report the login failure, pass `SsoOutcome::Failure(Status::requester())`
to your usual response method. The default ACS in current SP metadata must
support the delivery binding.
