# Update XML resource limit names

[How to upgrade from 0.8 to 0.9](README.md)

If you set custom XML limits, use the new field names and keep your existing
values.

| Old name | New name | What the limit measures |
| --- | --- | --- |
| `XmlLimits::max_nodes` | `XmlLimits::max_elements` | Elements in the XML document |
| `XmlLimits::max_text_bytes` | `XmlLimits::max_element_text_bytes` | Decoded direct text bytes per element |

If your `0.8.x` code checks `SamlError::Invalid` messages for these limits,
match the `limit` field of `SamlError::LimitExceeded`.

- For `max XML nodes`, match `ResourceLimit::XmlElements`.
- For `max XML text bytes`, match `ResourceLimit::XmlElementTextBytes`.

If you upgrade from an unreleased revision that has typed limit errors,
replace `ResourceLimit::XmlNodes` with `ResourceLimit::XmlElements`, and
`ResourceLimit::XmlTextBytes` with `ResourceLimit::XmlElementTextBytes`.

The formatted error labels are now `XML elements` and
`XML text bytes per element`.
