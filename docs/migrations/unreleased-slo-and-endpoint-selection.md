# Logout NameID, endpoint selection, and respond_slo issuer

This change is unreleased. Existing calls compile. Runtime logout and
Web Browser SSO routing changes.

## Match the LogoutRequest issuer in respond_slo

`Saml<Sp>::respond_slo` and `Saml<Idp>::respond_slo` compare the
`LogoutRequest` issuer with the peer descriptor entity ID before building a
`LogoutResponse`. A mismatch returns `SamlError::IssuerMismatch`. `expected`
is the request issuer. `actual` is the descriptor entity ID.

Who must change: a caller that responds through a descriptor for a different
party than the request issuer.

Pass the descriptor whose entity ID is that issuer. The same check already
applies to `respond_sso`. It keeps `InResponseTo` from being sent to another
party's `SingleLogoutService`. This rejection is library policy.

## Use the metadata default AssertionConsumerService

When an `AuthnRequest` names neither an ACS URL nor an ACS index, the
identity provider sends the response to the default `AssertionConsumerService`
for the response binding. `start_sso` uses the same endpoint as
`AssertionConsumerServiceURL` when the caller does not select an index.

The default, among endpoints for that binding, is the first with `isDefault`
true (`true` or `1`), otherwise the first whose `isDefault` is not false
(`false` or `0`), otherwise the first.

Who must change: a deployment whose first endpoint for the binding was not
the metadata default, and that relied on responses or AuthnRequests going to
that first URL.

Mark the endpoint that should receive traffic with `AcsEndpoint::mark_default`,
or remove `isDefault="false"` from the endpoint that should remain the
default.

## Send LogoutResponse to ResponseLocation

A `LogoutResponse` is sent to `ResponseLocation` on the first
`SingleLogoutService` for the binding when that attribute is present and
non-empty. Otherwise it is sent to `Location`. A `LogoutRequest` still uses
`Location`. `Metadata::get_single_logout_response_service` reads the response
URL.

Who must change: a peer that publishes `ResponseLocation` and still expects
the response at `Location`.

Accept the response at `ResponseLocation`, or omit that attribute when both
messages belong at `Location`. The service-provider `https` recommendation
checks the URL that is actually used.

## Accept every published endpoint location

Inbound `Destination` on `receive_sso` matches any `SingleSignOnService`
`Location` or `ResponseLocation` for the request binding. Inbound
`receive_slo` and `finish_slo` match any `SingleLogoutService` `Location` or
`ResponseLocation` for the binding. A mismatch still reports the first
`Location`.

Who must change: a deployment that published a second URL and relied on
saml-rs rejecting it.

Remove an endpoint that must not receive messages.

## Keep NameID format and qualifiers on LogoutRequest

`start_slo` copies `Format`, `NameQualifier`, `SPNameQualifier`, and
`SPProvidedID` from the `LogoutSubject` `NameID`. When that `NameID` has no
format, the first configured NameID format is used. A received
`LogoutRequest` exposes those attributes on `LogoutRequest::name_id`.

Who must change: a caller that copies a received logout `NameID` into
`OutstandingLogout`. A present `Format` is now compared with the assertion
`NameID`. An omitted `Format` still compares values only.
