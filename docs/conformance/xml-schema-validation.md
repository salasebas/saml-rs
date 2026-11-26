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

## Baseline receipt

Without a `SchemaValidator`, the typed receive APIs check the schema rules of
the values they read and return. They do not validate the rest of a message
against the SAML schemas. Core §3.2.1 lets a responder decide that a request
is invalid, and requires the `Requester` status only when it answers. No
OASIS rule tells a receiver to reject every schema-invalid message. A flow
record can add a stricter rule, and the
[SSO acceptance](web-browser-sso-acceptance.md) record states the rules for an
assertion the service provider relies on.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read a request or response `ID`, and a returned `InResponseTo`, as a string with a character other than whitespace. Read an `AuthnRequest` `ID` with XML whitespace collapsed | Library policy: reason not recorded. | Core §1.3.4, `RequestAbstractType`, `StatusResponseType` | Always |
| Read each returned `xs:boolean`, `xs:unsignedShort`, and `xs:dateTime` attribute by its datatype, and reject a value outside its lexical space. Return an `AttributeValue` as text whatever its `xsi:type` | Library policy: a typed result cannot hold a value that its datatype does not define, so the alternatives are to guess the value or to drop it. | Core §3.2.1, protocol and assertion schemas | Always |
| Read a protocol message `IssueInstant` only in the UTC form that ends in `Z` | Library policy: Core §1.3.3 makes another form an invalid SAML time value, and accepting an offset would convert a value that its sender had to write in UTC. | Core §1.3.3 | Always |
| Ignore an undeclared unqualified attribute, a child in an unread position, sibling order, text between children, and an empty `Extensions`, unless the flow record rejects it | Library policy: values are read by expanded name, so ignored content changes no returned value, and no receiver rule requires its rejection. | Core §3.2.1, §7.2 | `XmlPolicy::schema_validator` can reject it |
| Check XML names, `xs:ID`, and `xs:NCName` against the XML 1.0 Fifth Edition name characters | Library policy: the older table that XML Schema 1.0 cites rejects names that current XML accepts, such as one starting with U+037F, and generated IDs are ASCII. | XML 1.0 Fifth Edition §2.3, XML Schema Part 2 §3.3.7, §3.3.8 | Always |
