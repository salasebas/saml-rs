# Send AuthnRequests to a published https sign-on endpoint

This change affects a service provider whose identity provider publishes more
than one `SingleSignOnService` for the binding that `start_sso` uses, with an
`http` `Location` before an `https` one. No code fails to compile.

`ServiceProvider::start_sso` now sends the request to the first
`SingleSignOnService` for the binding with an `https` `Location`. When none is
`https`, it sends the request to the first one for the binding, as before. The
`Destination` of the request names the same URL.

In 0.8, `start_sso` sent the request to the first `SingleSignOnService` for
the binding, whatever its scheme.

SAML Profiles §4.1.3.3 recommends TLS for the HTTP exchanges that carry the
request. `IdpMetadata::single_sign_on_location` still returns the first
location for the binding, so it can name another URL than the one `start_sso`
uses.

No option restores the first endpoint. If the request must reach the `http`
endpoint, the identity provider metadata must stop publishing an `https`
endpoint for that binding.
