# Carry the supplied status in a custom LogoutResponse template

[How to upgrade from 0.5 to 0.6](README.md)

This breaks a `TemplatePolicy` whose `logout_response_template` does not
carry the top-level status `respond_slo` writes.

Who must change: a session participant or session authority that sets that
field on `SpConfig` or `IdpConfig`. Omitting `RespondSlo::status` still
writes `urn:oasis:names:tc:SAML:2.0:status:Success`.

Keep the placeholder on the top-level status code:

```xml
<samlp:Status>
  <samlp:StatusCode Value="{StatusCode}"/>
</samlp:Status>
```

`{StatusCode}` becomes that URI. After substitution, the top-level
`StatusCode` must equal the status supplied to `respond_slo`. A template
that keeps a different value returns `SamlError::Invalid`.

`{StatusCode}` holds only the top-level code. To send a subordinate code,
omit `logout_response_template` and pass `RespondSlo::status`. The default
renderer writes the top-level code and one subordinate code.
