# Handle responses with undeclared attributes on `Conditions`

The service provider now refuses a response when the selected assertion's
`Conditions`, or one of its `AudienceRestriction`, `OneTimeUse`, or
`ProxyRestriction` conditions, carries an attribute that its schema type does
not declare. `Conditions` declares `NotBefore` and `NotOnOrAfter`, and
`ProxyRestriction` declares `Count`. `AudienceRestriction` and `OneTimeUse`
declare none. Any other attribute counts, unqualified or in a namespace, such
as `Extra="1"` or `ext:Count="0"`.

These are still accepted, as before:

- namespace declarations,
- attributes in the XML Schema instance namespace, such as `xsi:type`,
  `xsi:schemaLocation`, `xsi:noNamespaceSchemaLocation`, and `xsi:nil`. The
  condition is evaluated by its element name whatever type `xsi:type` names,
- such attributes in another assertion of the response.

`finish_sso`, `accept_unsolicited_sso`,
`accept_unsolicited_sso_with_resolver`, and the two
`_with_outstanding_logout` variants return
`SamlError::UnrecognizedCondition`, the error they already return for an
unknown condition element. Its new `attribute` field names the attribute as
written, and `element` names the element that carries it. For an unknown
condition element, `attribute` is `None`. For HTTP-Artifact, artifact
resolution still returns the resolved response, and `finish_sso` with
`Inbound::artifact` returns the error. A qualified `NotBefore` or
`NotOnOrAfter` on `Conditions` still returns `SamlError::ProtocolProfile`.

Before, the session was created and the attribute was ignored.

No code change is needed unless an identity provider sends such an
attribute. Ask that identity provider to remove it. A pattern on
`UnrecognizedCondition` ends with `..`, as
[End field patterns with `..`](errors.md#end-field-patterns-with-) describes.
