# Logout NameID format and qualifiers

This change is unreleased. It applies to the release that first sends the
logout subject's full `NameID`.

Typed `start_slo` used to send the first local `name_id_format` as the
`NameID` `Format`, whatever the `LogoutSubject` held, and no qualifiers. It now
copies `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from
the `LogoutSubject` `NameId` into the `LogoutRequest`. `SsoSession` now reads
the same qualifiers from the assertion `NameID`, so
`SsoSession::logout_subject` carries them into logout.

## Add qualifier placeholders to a custom logout request template

Who must change: code that sets `TemplatePolicy::logout_request_template` and
starts typed Single Logout for a subject whose `NameId` has a qualifier. That
includes a subject taken from an `SsoSession` whose assertion `NameID` had one.
Session Authority generation, and session participant generation with producer
rules, now fail with `SamlError::ProtocolProfile` when the rendered `NameID`
drops or changes a qualifier. Session participant generation without producer
rules sends the template as written, so a template without the placeholders
still sends the `NameID` without its qualifiers.

Add the placeholders to the template's `NameID`. An attribute whose complete
value is a placeholder is omitted when the `NameId` has no value for it.

```xml
<saml:NameID NameQualifier="{NameQualifier}" SPNameQualifier="{SPNameQualifier}"
    Format="{NameIDFormat}" SPProvidedID="{SPProvidedID}">{NameID}</saml:NameID>
```

## Expect qualifiers on the SSO session NameID

Who must change: code that compares `SsoSession::name_id()` or
`SsoSession::subject()` with a `NameId` built by `NameId::new`. When the
assertion `NameID` has qualifiers, the session `NameId` now holds them and is
no longer equal to a `NameId` without them. Compare `NameId::value()` and
`NameId::format()` when only those matter.

## Set the NameID format on a service provider logout subject that needs one

A service provider's typed `start_slo` now omits `Format` when the
`LogoutSubject` `NameId` has none. That matches the assertion that established
the session, because an omitted `Format` means unspecified.

Who must change: service provider code that builds a `LogoutSubject` with
`NameId::new(value, None)` for an identity provider that expects a specific
format. Pass the format the session used, for example
`NameId::new(value, Some(NameIdFormat::EmailAddress))`. A subject from
`SsoSession::logout_subject` already carries the assertion's format.

An identity provider's typed `start_slo` still sends the first local
`name_id_format` for a `NameId` without a format. That is the `Format`
`respond_sso` writes in the assertion for the same `NameId`. A format set on
the `NameId` is now sent instead of the local one.

A custom logout request template whose `NameID` has `Format="{NameIDFormat}"`
keeps working: the attribute is omitted when no format is sent.

## Match the NameID format in a custom logout request template

Who must change: code that sets `TemplatePolicy::logout_request_template` with
a fixed `Format` on the `NameID`, such as
`Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"`, or with no
`Format` at all. Session Authority generation, and session participant
generation with producer rules, used to compare the rendered `Format` with the
first local `name_id_format`. They now compare it with the format sent for the
`LogoutSubject` `NameId` and fail with `SamlError::ProtocolProfile` when the
two differ. That includes a template without `Format` when a format other than
unspecified is sent. When no format is sent, the template must omit `Format`
or write `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`.

Write `Format="{NameIDFormat}"` in the template.
