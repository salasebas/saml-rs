# Rename the SOAP body type and channel variants

If you import `SoapProtocolMessage` or refer to `Absent` in any SOAP channel
attestation enum, update those references to compile.

| Old name | New name |
| --- | --- |
| `SoapProtocolMessage` | `SoapBodyElement` |
| `PartyAuthentication::Absent` | `PartyAuthentication::Unattested` |
| `MessageIntegrity::Absent` | `MessageIntegrity::Unattested` |
| `MessageConfidentiality::Absent` | `MessageConfidentiality::Unattested` |

Call `SoapBodyElement::from_envelope` to read the single XML element from a
SOAP 1.1 body. The result exposes its local name, namespace URI, and
standalone XML. Use a typed SAML receive operation to validate the message for
its protocol flow.

Use `SoapChannel::unattested()` when you supply none of the three channel
attestations. To attest some properties, pass `Unattested` for each property
you leave unspecified in `SoapChannel::new`.
