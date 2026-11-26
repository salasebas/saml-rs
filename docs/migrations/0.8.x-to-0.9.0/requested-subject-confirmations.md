# Answer requests for a confirmation method other than bearer

If you run an identity provider, `IdentityProvider::respond_sso` and
`respond_sso_artifact` now return `SamlError::Invalid` for a success response
when the `AuthnRequest` `Subject` has `SubjectConfirmation` elements and none
of them is a bearer confirmation, `urn:oasis:names:tc:SAML:2.0:cm:bearer`,
without an identifier or `SubjectConfirmationData`. Before, the identity
provider answered with a bearer assertion that did not meet the requested
confirmation.

The assertion carries only its own bearer confirmation, so it cannot meet a
request for holder-of-key or sender-vouches, or a bearer confirmation limited
to another recipient. SAML Core requires the identity provider to answer such
a request with an error status. The identity provider does not compare
`SubjectConfirmationData`, so it refuses every constrained bearer
confirmation.

To upgrade, answer such a request with `SsoOutcome::Failure` and
`Status::responder()`. `RequestedSubject::confirmations` returns the
requested `SubjectConfirmation` elements.

A request whose `Subject` has no `SubjectConfirmation`, or has at least one
bearer confirmation with only its `Method`, is answered as before. Service
providers must not send `SubjectConfirmation` in an `AuthnRequest` for Web
Browser SSO, so requests from conforming service providers are unaffected.
