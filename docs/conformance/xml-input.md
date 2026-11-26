# XML input limits and encoding

Every typed receive operation, at the identity provider and the service
provider and on every binding, parses received XML under the `XmlLimits` in
its provider's `XmlPolicy::limits`. `MetadataAggregate::from_xml` takes its
`XmlLimits` as an argument.

Normative text is XML 1.0 (Fifth Edition) §2.8 and §5.1, which make a
malformed XML declaration a fatal error, and §4.3.3, which defines the
character encodings an XML processor reads. Namespaces in XML 1.0 (Third
Edition) §7 and §8 make a processor report an element or attribute name that
is not a `QName`. XML 1.0 sets no resource limits, so each limit is library
policy.

## Support

| Feature | Section | XML processor |
| --- | --- | --- |
| Report an XML declaration that does not match `XMLDecl` as a fatal error | XML 1.0 §2.8, §5.1 | Supported |
| Report an element or attribute name that does not match `QName` | XML 1.0 §2.3, Namespaces in XML 1.0 §7, §8 | Supported |
| Read an entity encoded in UTF-8, with or without a byte order mark | XML 1.0 §4.3.3 | Supported |
| Read an entity encoded in UTF-16 | XML 1.0 §4.3.3 | Not supported |
| Read an entity in another encoding that its `encoding` declaration names | XML 1.0 §4.3.3 | Not supported |
| Report an `encoding` declaration that does not match the bytes as a fatal error | XML 1.0 §4.3.3 | Not supported |

## Rules

### XML processor: browser binding receive operations

Code: `src/flow.rs`, `src/browser/input.rs`, `src/xml/mod.rs`, `src/xml/dom.rs`

The browser bindings decode the base64 or DEFLATE payload to bytes and read
them as XML. SOAP envelopes and metadata reach the crate as Rust strings that
the caller decoded.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read a received browser binding payload as UTF-8, with or without a byte order mark | Mandatory | XML 1.0 §4.3.3 | Always |

### XML processor: received messages, SOAP envelopes, and metadata

Code: `src/xml/dom.rs`, `src/xml/dom/element.rs`, `src/xml/name.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an XML declaration that does not match `XMLDecl`: `version` with a `1.x` number, then optional `encoding` and `standalone`, in that order, separated by whitespace, with no other pseudo-attribute | Mandatory | XML 1.0 §2.8, §2.9, §4.3.3, §5.1 | Always |
| Reject an element or attribute name that does not match `QName`: one `NCName`, or two joined by one colon, of XML 1.0 Fifth Edition name characters | Mandatory | XML 1.0 §2.3, Namespaces in XML 1.0 §7, §8 | Always |

## Library policies

### Document type declarations

Code: `src/xml/dom.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Refuse a received browser binding message or metadata document that has a document type declaration, with or without an internal subset, before reading its elements | A DTD can declare entities that expand the input or that load external resources, so refusing it keeps entity expansion and external entity attacks out of the parser. | XML 1.0 §2.8, §5.1 | Always |

[Artifact resolution](artifact-resolution.md#soap-receiver-policies) keeps
the same refusal for a received SOAP envelope, because SOAP 1.1 §3 forbids a
document type declaration in a SOAP message.

### Resource limits

Code: `src/xml/dom.rs`, `src/xml/dom/element.rs`

The values are the defaults of `XmlLimits::default()`. Byte counts are UTF-8
bytes. Attribute values and text are counted after entity and character
references are decoded.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Refuse input over 1 MiB (1,048,576 bytes) before parsing | It bounds the memory and time an unauthenticated message can use, and SAML messages are a few kilobytes. | — | `XmlLimits::max_bytes` |
| Refuse elements nested deeper than 1,024 levels | It bounds the work of walking the tree, and SAML messages and metadata nest about a dozen levels. | — | `XmlLimits::max_depth` |
| Refuse a document with more than 50,000 elements | It bounds the memory of the parsed tree, and a SAML message has a few hundred elements, though a federation aggregate can have more. | — | `XmlLimits::max_elements` |
| Refuse an element with more than 64 attributes, namespace declarations included | SAML elements carry about a dozen attributes, and the limit bounds the work for one element. | — | `XmlLimits::max_attributes_per_element` |
| Refuse more than 64 namespace declarations in scope at once | The cost of resolving and canonicalizing each element grows with the declarations in scope, and SAML messages declare about ten. | — | `XmlLimits::max_attributes_per_element` |
| Refuse an attribute value over 16 KiB (16,384 bytes) | SAML attribute values are identifiers, instants, and URIs, far below that size. | — | `XmlLimits::max_attribute_value_bytes` |
| Refuse more than 1 MiB (1,048,576 bytes) of direct text in one element | Base64 certificates and ciphertext are the largest text values, and with the default input limit no text reaches this one first. | — | `XmlLimits::max_element_text_bytes` |

### Character encoding

Code: `src/xml/mod.rs`, `src/xml/dom/element.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Read the document as UTF-8 whatever its `encoding` declaration names | Reason not recorded. | XML 1.0 §4.3.3 | Always |

## Not supported

- Reading an entity encoded in UTF-16. Mandatory for an XML processor, XML 1.0
  §4.3.3. A UTF-16 payload, like any payload that is not UTF-8, is refused as
  malformed XML.
- Reading another encoding that an `encoding` declaration names. XML 1.0
  §4.3.3 does not require a processor to support it. The document is read as
  UTF-8, as the [character encoding policy](#character-encoding) says.
- Reporting an `encoding` declaration that does not match the bytes as a fatal
  error. Mandatory for an XML processor without external encoding
  information, XML 1.0 §4.3.3.
