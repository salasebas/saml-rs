# Encrypt for a usable key and write its certificate

## Logout and name identifier management skip an unusable key

`StartSlo::identifier_encryption` and
`StartNameIdManagement::identifier_encryption` with
`IdentifierEncryptionPolicy::EncryptIdentifiers` now encrypt for the first
peer encryption key that the configured algorithms can use. They read the
keys from the peer metadata the same way an identity provider does for an
SSO response. Before, they used the first encryption certificate in the peer
metadata and failed with `SamlError::Crypto` when it did not load or the
crypto provider could not encrypt for it, such as an EC key or an RSA key
too small for the key transport. Now they try the next key.

A peer without an encryption certificate still returns
`SamlError::MissingMetadata`. A peer without a usable key still returns the
`SamlError::Crypto` error of its first key. You do not need to change code.

## Each EncryptedKey names the certificate it was encrypted for

Every `xenc:EncryptedKey` that the crate writes now carries a `ds:KeyInfo`
with the peer certificate it encrypted for:

```xml
<xenc:EncryptedKey>
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data>
  </ds:KeyInfo>
  <xenc:CipherData>...</xenc:CipherData>
</xenc:EncryptedKey>
```

This covers SSO responses, `LogoutRequest` identifiers, and name identifier
management identifiers. Metadata §2.4.1.1, as amended by Approved Errata 05
E68, recommends that the encrypting party say which key it used. A peer with
several published keys can then pick its matching private key. OpenSAML
5.2.0, and so the Shibboleth identity provider, writes the same element.

Each encrypted element grows by the base64 certificate, about 1.3 KB for a
typical 2048-bit RSA certificate. An HTTP-Redirect message with encrypted identifiers
grows by about that much per element. You do not need to change code.

## KeyInfo outside the XML Signature namespace holds no key

`Metadata`, `SpMetadata`, `IdpMetadata`, `SpDescriptor`, and `IdpDescriptor`
now read a certificate only from a `ds:X509Certificate` in a `ds:X509Data` of
the `ds:KeyInfo` of a `md:KeyDescriptor`, with
`ds` bound to `http://www.w3.org/2000/09/xmldsig#`. Before, they matched
these elements by local name, so an element such as `<KeyInfo>` in the
metadata namespace, or in any other namespace, gave a signing or encryption
certificate.

Metadata that leaves `KeyInfo` unprefixed under a default metadata namespace
is schema-invalid, and other SAML implementations read no key from it.
With such metadata, `x509_certificates` now returns no certificate for that
`KeyDescriptor`. Signature verification then fails, and encryption returns
`SamlError::MissingMetadata`. To fix it, ask the peer to publish valid
metadata, or bind the XML Signature namespace in your copy:

```xml
<!-- Before -->
<KeyInfo><X509Data><X509Certificate>MIIC...</X509Certificate></X509Data></KeyInfo>
<!-- After -->
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
```
