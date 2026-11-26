# Accept SSO responses whose assertions name the principal differently

This change affects service providers that receive SSO responses with more
than one assertion, and applications that match `SamlError::PrincipalMismatch`.

`ServiceProvider::finish_sso` and the unsolicited SSO methods no longer compare
the `Subject` of the other assertions with the assertion that the session
reads. A response is now accepted when another assertion has a different
`NameID` value, `Format`, `NameQualifier`, or `SPNameQualifier`, or has no
`NameID`. Profiles §4.1.4.2, as corrected by E26, lets the `Subject` content of
the assertions differ. The session still reads only the selected assertion,
and every assertion must still have the identity provider as its `Issuer`.

`SamlError::PrincipalMismatch` is removed. Delete the match arms that name it.
