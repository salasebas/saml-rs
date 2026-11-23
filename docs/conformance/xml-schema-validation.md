# Optional XML schema validation

The callback is an application policy for inbound XML. It is not an XSD engine
and does not establish conformance with a complete SAML profile.

| Behavior | Actor | Direction and condition | Basis and scope |
| --- | --- | --- | --- |
| Run the configured schema callback after baseline parsing and before accepting input | SP, IdP, and metadata consumer | Inbound, only when `XmlPolicy::schema_validator` is `Some` | Library policy. [Core §1.1](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) makes schemas and normative prose authoritative and notes that prose can impose additional constraints. It does not specify this callback API. A callback rejection may exceed OASIS receiver rules; its schema set and additional restrictions belong to the application |
| Include protocol XML, SOAP envelopes, and decrypted protocol documents | SP and IdP | Received browser SSO, logout, artifact resolution, and name identifier management | Library policy. A successful callback does not replace signature, trust, correlation, audience, time, or replay checks. Internal DOM reparses of already checked documents and locally generated XML do not invoke it |
| Validate the original metadata document with an explicit import policy | Metadata consumer | `from_metadata_xml_with_policy`, raw `from_xml_with_policy`, and `Metadata::parse_with_policy` | Library policy. Metadata import precedes the local role configuration. Constructors without a policy install no callback |

The [protocol schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd)
imports the assertion and XML Signature schemas. The
[metadata schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd)
imports assertion, XML Signature, XML Encryption, and XML namespace schemas.
Core §7.2 defines wildcard extension points, including lax processing. A
validator must preserve their schema semantics and support the schemas needed
by the configured flows. Approved Errata 05 adds no callback or process-global
configuration requirement.

Baseline parser limits and DOCTYPE rejection always apply before the callback.
The library has no process-global schema state or callback lock. Standalone
DOM, extractor, signature, and encryption utilities have no implicit schema
policy.
