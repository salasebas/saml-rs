# Logout NameID format and qualifiers

This change is unreleased. It applies to the release that first sends the
logout subject's full `NameID`.

Typed `start_slo` used to send the first local `name_id_format` as the
`NameID` `Format`, whatever the `LogoutSubject` held, and no qualifiers. It now
sends the `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` of
the `LogoutSubject` `NameId`. `SsoSession` now reads the same qualifiers from
the assertion `NameID`, so `SsoSession::logout_subject` carries them into
logout.

Go to the sections that match the code:

- It sets `TemplatePolicy::logout_request_template`:
  [Update a custom logout request template](#update-a-custom-logout-request-template).
- A service provider builds its own `LogoutSubject`:
  [Set the format on a service provider logout subject](#set-the-format-on-a-service-provider-logout-subject).
- An identity provider passes a `NameId` with a format or qualifiers to
  `start_slo`:
  [Check the NameID an identity provider passes to logout](#check-the-nameid-an-identity-provider-passes-to-logout).
- It compares the `NameId` of an `SsoSession`:
  [Expect qualifiers on the SSO session NameID](#expect-qualifiers-on-the-sso-session-nameid).

A service provider that passes `SsoSession::logout_subject` to `start_slo`
with the default template has nothing to change.

## Update a custom logout request template

Who must change: code that sets `TemplatePolicy::logout_request_template`.

Write the four `NameID` attributes as placeholders:

```xml
<saml:NameID NameQualifier="{NameQualifier}" SPNameQualifier="{SPNameQualifier}"
    Format="{NameIDFormat}" SPProvidedID="{SPProvidedID}">{NameID}</saml:NameID>
```

An attribute whose complete value is a placeholder is omitted when the request
has no value for it.

A template left as it is behaves in one of two ways.

Session Authority generation, and session participant generation with producer
rules, now compare the rendered `NameID` attributes with the ones sent for the
`LogoutSubject`. They used to compare `Format` with the first local
`name_id_format` and reject every qualifier. They fail with
`SamlError::ProtocolProfile` when the template:

- has no qualifier placeholders and the `NameId` has a qualifier. That includes
  a subject from an `SsoSession` whose assertion `NameID` had one;
- has a fixed `Format`, such as
  `Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"`, that is
  not the format sent;
- has no `Format` and a format other than unspecified is sent.

When the request has no `Format`, the template must omit `Format` or write
`urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`.

Session participant generation without producer rules sends the template as
written. A template without the qualifier placeholders still sends the `NameID`
without its qualifiers.

## Set the format on a service provider logout subject

Who must change: service provider code that builds a `LogoutSubject` with
`NameId::new(value, None)` for an identity provider that expects a specific
format. A service provider's `start_slo` used to send the first local
`name_id_format` for that `NameId`. It now omits `Format`.

Pass the format the session used:

```rust
let name_id = NameId::new(value, Some(NameIdFormat::EmailAddress));
```

A subject from `SsoSession::logout_subject` already carries the assertion's
format and qualifiers.

## Check the NameID an identity provider passes to logout

Who must change: identity provider code that passes a `NameId` with a format
or qualifiers to typed `start_slo`, for example the requested subject of an
`AuthnRequest`. `start_slo` used to send the first local `name_id_format` and
drop the qualifiers. It now sends what the `NameId` holds.

Pass the `NameID` the assertion carried:

- If the `NameId` has a format, pass the format it had in `respond_sso` or
  `initiate_sso`.
- If the `NameId` has qualifiers, pass them only when a custom login response
  template wrote them into the assertion. `respond_sso` and `initiate_sso`
  write the `NameID` value and `Format` only. Otherwise pass
  `NameId::new(value, format)`.

A `NameId` without a format needs no change. `start_slo` still sends the
`Format` that `respond_sso` writes for it.

## Expect qualifiers on the SSO session NameID

Who must change: code that compares `SsoSession::name_id()` or
`SsoSession::subject()` with a `NameId` built by `NameId::new`. When the
assertion `NameID` has qualifiers, the session `NameId` now holds them and is
no longer equal to a `NameId` without them.

Compare `NameId::value()` and `NameId::format()` when only those matter.

The rules behind these changes are in
[Single Logout conformance](../conformance/single-logout.md).
