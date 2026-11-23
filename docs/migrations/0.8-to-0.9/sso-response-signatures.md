# Keep response signatures for SPs with several SAML 2.0 roles

[How to upgrade from 0.8 to 0.9](README.md)

If any of the peer's SAML 2.0 `SPSSODescriptor` elements sets
`WantAssertionsSigned` to `true` or `1`, the IdP now signs the assertion. The
previous behavior treated this flag as false when the peer published several
SAML 2.0 SP roles.

For such a peer that also requires a signature on the outer `Response`, pass
`RespondSso::post().sign_response()` where you used `RespondSso::post()`.
For an artifact-delivered response, use
`RespondSso::artifact(delivery).sign_response()`. The IdP then signs both
the assertion and the response.
