# Prepare SOAP payloads without processing instructions

[How to upgrade from 0.8 to 0.9](README.md)

This change affects applications that pass their own SAML XML to a SOAP
constructor or to `IdentityProvider::issue_artifact`. Previously, an ordinary
processing instruction inside the SAML element could reach the SOAP body.
`SoapRequest::try_new`, `SoapResponse::try_new`, and
`IdentityProvider::issue_artifact` now return `SamlError::Xml` for that input.

Configure your XML producer to omit processing instructions inside the SAML
element. If the XML carries a signature, regenerate and sign the message
before passing it to `saml-rs`. Removing an instruction from signed XML can
change the digest. You can still pass an XML document with a leading XML
declaration. The SOAP body contains only the document element.
