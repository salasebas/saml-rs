# How to upgrade from 0.3 to 0.4

Upgrade from the latest `0.3` release to `0.4`. The
[changelog](../../../CHANGELOG.md) lists every other change.

Messages produced by the standard `saml-rs` APIs already carry the required
timestamps. You still need to update code that builds those messages itself,
plus any public `IdpConfig` struct literal and any call to
`RespondSlo::signing`.

## Topics

- [Check timestamp requirements](timestamps.md)
- [Update SSO messages and issuance settings](sso.md)
- [Update logout messages and response signing](logout.md)

## Checklist

- Add a UTC `IssueInstant` ending in `Z` to every custom `AuthnRequest`.
- Add `request.issueInstant` to hand-built `FlowResult` fixtures.
- Add a UTC `IssueInstant` ending in `Z` to every custom SSO `Response` and
  selected `Assertion`.
- Add `response.issueInstant` and `assertion.issueInstant` to hand-built SSO
  `FlowResult` fixtures.
- Add `issuance_lifetime` to public `IdpConfig` struct literals, or keep the
  builder and its five-minute default.
- Add exactly one unqualified `NotOnOrAfter="{NotOnOrAfter}"` attribute to
  custom LogoutRequest templates used by `Saml<Idp>::start_slo`.
- Store both pending `issued_at` and `expires_at` for typed Session Authority
  logout snapshots.
- Leave a generic inbound LogoutRequest valid when `NotOnOrAfter` is absent.
- Add a UTC `IssueInstant` ending in `Z` to every custom `LogoutRequest`.
- Add `request.issueInstant` to hand-built LogoutRequest fixtures, and
  `request.notOnOrAfter` when the wire message has it.
- Update tests that previously accepted an expired LogoutRequest
  `NotOnOrAfter`.
- Keep `replay_retention` for typed LogoutRequest replay when `NotOnOrAfter`
  is absent. When it is present, replay uses the skew-adjusted deadline.
- Add a UTC `IssueInstant` ending in `Z` to every custom `LogoutResponse`.
- Add `response.issueInstant` to hand-built LogoutResponse fixtures.
- Update custom LogoutResponse templates: required root attributes, correlated
  `InResponseTo`, entity-format `Issuer`, and a final `Status`, in that child
  order.
- Remove root `ds:Signature` elements from custom LogoutResponse templates.
- Remove `RespondSlo::signing(...)`. Typed responses are always signed.
- Configure a signing key and certificate for every typed SLO responder.
- Update tests that expected inbound leap seconds to be rejected.
- Update tests or telemetry that expect another error for a malformed unsigned
  request or response.

[All migration guides](../README.md)
