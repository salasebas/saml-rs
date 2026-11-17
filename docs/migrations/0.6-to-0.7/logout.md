# Update logout subjects, templates, and responses

[How to upgrade from 0.6 to 0.7](README.md)

If you customise `TemplatePolicy::logout_request_template`, use the subject's
NameID attributes as placeholders:

```xml
<saml:NameID NameQualifier="{NameQualifier}" SPNameQualifier="{SPNameQualifier}"
	Format="{NameIDFormat}" SPProvidedID="{SPProvidedID}">{NameID}</saml:NameID>
```

An attribute whose complete value is a placeholder is omitted when there is no
value for it. Session participant generation without producer rules sends the
template as written, so add the placeholders there too.

`start_slo` now sends the subject's format and qualifiers rather than the
first local format. A template that disagrees can return
`SamlError::ProtocolProfile`. For SP logout, use `SsoSession::logout_subject`
or supply the session's format and qualifiers yourself.
For IdP logout, pass what the issued assertion carried.

If you set `SPProvidedID` on an issued subject, ensure the SP supplied that
alternative identifier. SSO responses now write it instead of dropping it.
Login response templates cannot represent it and now return `SamlError::Invalid`.
Drop the template or pass `None`. Standard response generation still omits
`NameQualifier` and `SPNameQualifier`. Send those in logout only if a custom
response template wrote them into the assertion.

Accept logout responses at a peer's non-empty `ResponseLocation`, or omit
that attribute to use `Location` for both directions. Under SP generation
rules, use HTTPS or select `RespondSlo::allow_http_single_logout`.
Pass `respond_slo` the descriptor matching the request issuer to avoid
`SamlError::IssuerMismatch`.

If you read SOAP logout `BindingContext`, expect protocol XML in `context`
rather than base64, and an empty `entity_endpoint` on responses.

If you handle refused logout through `SamlError::StatusNotSuccess`, handle
signature, issuer, correlation, and destination errors as failed logout too.
Typed and raw logout now perform their authentication and correlation checks
before reporting non-Success status. Under
`LogoutSignaturePolicy::AllowUnsignedForCompatibility`, an unsigned response
still reports its status after the correlation checks. See
[Single Logout](../../conformance/single-logout.md).
