# Give AuthnRequests a ProviderName with visible text

`ServiceProvider::start_sso` now returns `SamlError::Invalid` when
`StartSso::provider_name` is empty or has only spaces, tabs, carriage
returns, and line feeds. Before, it wrote the blank value as the
`ProviderName` attribute. SAML Core §1.3.1 requires a SAML string to contain
at least one non-whitespace character.

This affects a service provider that passes a blank name. No code fails to
compile. Leave out `provider_name` to omit the attribute, or pass a name with
visible text.
