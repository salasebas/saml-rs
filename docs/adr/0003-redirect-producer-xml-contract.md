# Keep public Redirect producers limited to binding operations

Accept the existing binding-only contract of `binding::build_redirect_url` and
`binding::build_redirect_octet`. These public producer helpers perform the
binding and signature operations described by their rustdoc. They do not
promise full XML well-formedness, schema validation, or SAML message validation.
A successful return supplies encoded bytes, not a validated message.

Defer stricter XML rejection. No behavior-changing fix is approved by this
record. Input outside the documented scope has no promised repaired output or
exhaustive rejection. Existing scanner errors and resource limits still apply.
This decision preserves behavior, public errors, defaults, and signatures.
It requires no migration entry.

This resolves the investigation in [issue #529](https://github.com/salasebas/saml-rs/issues/529).
It does not classify the observation as an authentication bypass or a release
blocker. No valid accepted-message failure was demonstrated.

## Binding scope and standards

The obligated actor is the sender encoding a SAML protocol message for
HTTP-Redirect with DEFLATE. When the protocol message has an XML signature,
[OASIS SAML Bindings §3.4.4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
requires its removal before compression and a new signature over the encoded
message. Nested signatures remain. The helpers split this work as follows:

- `build_redirect_url` rejects a direct-child `ds:Signature` rather than emit
  an unsigned URL that still contains the protocol signature.
- `build_redirect_octet` removes direct-child `ds:Signature` elements and
  prepares the query to sign. The caller still signs and attaches it.

The [protocol schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd)
places `ds:Signature` directly under the request or response root.
These observations cover outbound binding construction, not inbound
acceptance or conformance with a whole SAML profile.

[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.pdf)
E1 clarifies RelayState protection, and E90 adds RelayState sanitization
requirements. Neither changes signature removal into a full XML-validation
contract for these helpers. Retaining this API boundary is a library contract
decision, not an OASIS permission to send malformed XML.

[XML 1.0 §2.3, production 10, and §3.1](https://www.w3.org/TR/xml/)
exclude a literal `<` from a quoted attribute value. `&lt;` is the escaped
representation. An escaped attribute can be well formed without satisfying
its schema datatype. In particular, `ds:Signature/@Id` has type `xs:ID` in the
[XML Signature schema](https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd).
The decoded `a<b` is outside the
[`xs:ID` lexical space](https://www.w3.org/TR/xmlschema-2/#ID).
The probe below tests XML well-formedness, not schema validity or signature
verification. Its minimal `<r>` documents are not SAML messages.

## Evidence and compatibility impact

The investigation ran against `eba129dc567c3c432732c9ec26bef331c5cff51b`.
The original audit used `6500e0ba9608ca366c4c318d1616f293a578ae51`.
The relevant implementation remains in [redirect.rs](../../src/binding/redirect.rs).
`protocol_signature_spans` reads namespace-resolved events, and `element_start`
finds the last raw `<` before a signature start event ends. It therefore
selects the `<` inside an already-malformed `Id="a<b"` attribute.
`remove_spans` retains the partial `<ds:Signature Id="a` start tag.
With `Id="a&lt;b"`, the helper removes the whole signature.

The [quick-xml NsReader documentation](https://docs.rs/quick-xml/0.42.0/quick_xml/reader/struct.NsReader.html)
describes a low-level event reader with namespace resolution. The Redirect
scanner does not call the local DOM's attribute validation.
The [DOM parser](../../src/xml/dom.rs) explicitly rejects raw `<` in an attribute,
undeclared prefixes, multiple roots, and duplicate attributes in these cases.

Both Redirect helpers currently return success for the four extra inputs in
the probe. Replacing the scanner with `dom::parse` would turn each success
into an error, including the unsigned path where no signature needs removal.
The existing `redirect_round_trip` and
`redirect_octet_preserves_encoded_bytes_and_parameter_order` unit tests also
use undeclared `samlp` prefixes. Such a replacement would break those cases.
This is concrete compatibility impact, not evidence that deployed callers
rely on malformed input. No downstream caller survey or performance
measurement was made.

The input-byte, node, depth, namespace-binding, DOCTYPE, and event-error checks
already present in the scanner remain in place. Full DOM validation would also
change validation coverage and error precedence. Any such change needs its own
public error contract and compatibility decision.

## Reproduction record

This temporary example ran with the following command and exited 0:

```sh
cargo run -p saml-rs --example redirect_contract_probe --no-default-features
```

The example source appears below. It uses only existing dependencies.
The temporary file `examples/redirect_contract_probe.rs` is not part of the
change. The query decoder percent-decodes `SAMLRequest`, base64-decodes the
value, and inflates raw DEFLATE before the DOM checks.

```rust
use saml_rs::binding::{
	base64_decode, build_redirect_octet, build_redirect_url, deflate_raw_decode,
};
use saml_rs::constants::ParserType;
use saml_rs::xml::dom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let root = r#"<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#;
	for (name, content) in [
		("literal", r#"<ds:Signature Id="a<b"></ds:Signature>"#),
		("escaped", r#"<ds:Signature Id="a&lt;b"></ds:Signature>"#),
		("ordinary", r#"<ds:Signature Id="ab"></ds:Signature>"#),
	] {
		let xml = format!("{root}{content}</r>");
		let octet = build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg")?;
		let encoded = url::form_urlencoded::parse(octet.as_bytes())
			.find(|(name, _)| name == "SAMLRequest")
			.map(|(_, value)| value.into_owned())
			.ok_or("missing SAMLRequest")?;
		let output = String::from_utf8(deflate_raw_decode(&base64_decode(&encoded)?)?)?;
		println!("{name}: input_dom={} output_dom={} output={output:?}",
			dom::parse(&xml).is_ok(), dom::parse(&output).is_ok());
	}
	for (name, xml) in [
		("literal_no_signature", r#"<r Id="a<b"/>"#),
		("undeclared_prefix", "<samlp:AuthnRequest/>"),
		("multiple_roots", "<r/><s/>"),
		("duplicate_attribute", r#"<r a="1" a="2"/>"#),
	] {
		println!("{name}: dom={} unsigned={} octet={}",
			dom::parse(xml).is_ok(),
			build_redirect_url("https://idp.example/sso", ParserType::SamlRequest, xml, None).is_ok(),
			build_redirect_octet(ParserType::SamlRequest, xml, None, "sig-alg").is_ok());
	}
	Ok(())
}
```

The observed output was:

```text
literal: input_dom=false output_dom=false output="<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Signature Id=\"a</r>"
escaped: input_dom=true output_dom=true output="<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></r>"
ordinary: input_dom=true output_dom=true output="<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></r>"
literal_no_signature: dom=false unsigned=true octet=true
undeclared_prefix: dom=false unsigned=true octet=true
multiple_roots: dom=false unsigned=true octet=true
duplicate_attribute: dom=false unsigned=true octet=true
```

These results reproduce malformed-input handling in a producer helper.
They do not exercise an authenticated inbound flow or show a receiver
accepting a malformed message.

## Follow-up boundary

A stricter contract remains deferred. If maintainers approve a fix, a separate
behavior-changing issue must name the inputs to reject, the affected public
helpers, and the exact `SamlError` contract, including error precedence.
It must require a regression that fails before the fix, retain the escaped
attribute control, and specify the caller migration. This investigation
creates no implementation issue because it approves no behavior change.

The resource-limit refactor in
[issue #526](https://github.com/salasebas/saml-rs/issues/526) remains independent.
It must preserve the scanner's behavior and must not route it through the DOM
or add rejection under cover of sharing limit primitives.
