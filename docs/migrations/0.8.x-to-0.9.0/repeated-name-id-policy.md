# Answer AuthnRequests with more than one `NameIDPolicy`

`IdentityProvider::receive_sso` now returns `SamlError::AuthnRequestRefused`
for an `AuthnRequest` with more than one `NameIDPolicy`.
`RefusedAuthnRequest::reason` returns
`AuthnRequestRefusalReason::RepeatedNameIdPolicy`.

In 0.8, `receive_sso` returned such a request, and
`AuthnRequest::name_id_policy` returned `None`. Both policies were dropped, so
the identity provider could issue an identifier that one of them excluded.
`AuthnRequestType` allows one `NameIDPolicy`, and Core §3.4.1.1 binds the
identity provider to the policy the service provider requests.

To upgrade, answer the refusal as
[Answer AuthnRequests refused for their signature or age](authn-request-signature-and-age-refusals.md)
describes. Pass it to `respond_sso_refusal` or `respond_sso_refusal_artifact`,
which send a correlated `Requester` response. `AuthnRequestRefusalReason` is
`#[non_exhaustive]`, so a `match` on it already has a wildcard arm. Add a
`RepeatedNameIdPolicy` arm if you handle that reason apart from the others.

An unsigned request that must be signed is still refused with `Unsigned`, even
when it also has more than one `NameIDPolicy`.
