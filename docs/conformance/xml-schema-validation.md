# Optional XML schema validation

`XmlPolicy::schema_validator` is an application callback for received XML. It
is not an XSD engine and does not claim conformance with a SAML profile. Core
§1.1 makes the schemas and the normative prose authoritative. No OASIS
document defines this callback.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Run the callback on received protocol XML, SOAP envelopes, and decrypted protocol documents after the baseline parse | Library policy: the application owns its schema set, so a rejection can go beyond OASIS receiver rules. | Core §1.1 | `XmlPolicy::schema_validator` |
| Run it on the original metadata document only when the import names a policy | Library policy: metadata is imported before the role configuration exists. | Core §1.1 | `XmlPolicy::schema_validator` on `IdpDescriptor::from_metadata_xml_with_xml_policy`, `SpDescriptor::from_metadata_xml_with_xml_policy`, `metadata::IdpMetadata::from_xml_with_policy`, `metadata::SpMetadata::from_xml_with_policy`, and `metadata::Metadata::parse_with_policy` |
| Keep every other check | Library policy: a valid schema does not prove signature, trust, correlation, audience, time, or replay. | — | Always |

Parser limits and DOCTYPE rejection run before the callback. The callback does
not run on XML the crate generates or on reparses of a document it already
checked. A validator supports the schemas of the configured flows and keeps the
lax processing of the Core §7.2 extension points.
