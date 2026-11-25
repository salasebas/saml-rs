# XML input limits and encoding

Every typed receive operation parses received XML under the `XmlLimits` in its
provider's `XmlPolicy::limits`. `MetadataAggregate::from_xml` takes its
`XmlLimits` as an argument. XML 1.0 sets no resource limits, so each limit is
library policy.

## Resource limits

The values are the defaults of `XmlLimits::default()`. Byte counts are UTF-8
bytes. Attribute values and text are counted after entity and character
references are decoded.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Refuse input over 1 MiB (1,048,576 bytes) before parsing | Library policy: it bounds the memory and time an unauthenticated message can use, and SAML messages are a few kilobytes. | — | `XmlLimits::max_bytes` |
| Refuse elements nested deeper than 1,024 levels | Library policy: it bounds the work of walking the tree, and SAML messages and metadata nest about a dozen levels. | — | `XmlLimits::max_depth` |
| Refuse a document with more than 50,000 elements | Library policy: it bounds the memory of the parsed tree, and a SAML message has a few hundred elements. Raise it for a federation aggregate. | — | `XmlLimits::max_elements` |
| Refuse an element with more than 64 attributes, namespace declarations included | Library policy: SAML elements carry about a dozen attributes, and the limit bounds the work for one element. | — | `XmlLimits::max_attributes_per_element` |
| Refuse more than 64 namespace declarations in scope at once | Library policy: the cost of resolving and canonicalizing each element grows with the declarations in scope, and SAML messages declare about ten. | — | `XmlLimits::max_attributes_per_element` |
| Refuse an attribute value over 16 KiB (16,384 bytes) | Library policy: SAML attribute values are identifiers, instants, and URIs, far below that size. | — | `XmlLimits::max_attribute_value_bytes` |
| Refuse more than 1 MiB (1,048,576 bytes) of direct text in one element | Library policy: base64 certificates and ciphertext are the largest text values, and with the default input limit no text reaches this one first. | — | `XmlLimits::max_element_text_bytes` |

The namespace limit has no field of its own. It uses the value of
`max_attributes_per_element`, so raising one raises the other.

## Character encoding

The browser bindings decode the base64 or DEFLATE payload to bytes and read
them as XML. SOAP envelopes and metadata reach the crate as Rust strings that
the caller decoded.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read a received browser binding payload as UTF-8, with or without a byte order mark, and refuse bytes that are not UTF-8 | Mandatory | XML 1.0 §4.3.3 | Always |
| Read the document as UTF-8 whatever its `encoding` declaration names | Library policy: reason not recorded. | XML 1.0 §4.3.3 | Always |

## Not implemented

- Reading an entity encoded in UTF-16. Mandatory for an XML processor, XML 1.0
  §4.3.3. A UTF-16 payload is refused as malformed XML.
- Reporting an `encoding` declaration that does not match the bytes as a fatal
  error. Mandatory for an XML processor without external encoding
  information, XML 1.0 §4.3.3.
