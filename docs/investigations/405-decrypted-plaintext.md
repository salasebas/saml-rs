# Decrypted XML plaintext corruption

[Issue #405](https://github.com/salasebas/saml-rs/issues/405) is reproducible
with bergshamra 0.12.0. This investigation adds reproductions, not a runtime
fix. The issue stays open until an upstream correction is available and the
regression tests run without `#[ignore]`.

## Observed behavior

The tests enter through `Saml<Sp>::finish_sso` over HTTP-POST. They encrypt
literal XML bytes, so the producer does not canonicalize away the input under
test. Each Response is signed after encryption, including CBC responses.

| Plaintext NameID content | Encrypted assertion or identifier | Signed then encrypted assertion |
| --- | --- | --- |
| `<![CDATA[<b></b>]]>` | Accepted as `<b/>` | Signature verification fails |
| `<![CDATA[x <b /> y]]>` | Accepted as `x <b/> y` | Signature verification fails |
| `alice>` | XML parsing fails | XML parsing fails |

The signed assertion control verifies and exposes the expected value before
encryption. An ordinary `alice` value succeeds through all three paths with
the released dependency. Existing encryption tests cover ordinary serialized
values, not these literal CDATA and character-data representations.

Run the reproductions against the released dependency:

```sh
cargo nextest run -p saml-rs --test encrypted_assertion_elements \
  --run-ignored only -E 'test(preserves_xml_text)'
```

All three tests fail. They remain explicitly ignored while the dependency
cannot satisfy their requirements. Their expected values describe the correct
XML text, rather than treating the corrupt output as correct.

## Root cause

The upstream
[`decrypt_to_bytes` implementation](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-enc/src/decrypt.rs#L30)
calls `replace_encrypted_data_bytes` before returning. Both public decryption
functions therefore return rewritten output. Switching saml-rs to
`decrypt_to_bytes` alone does not fix the bug.

[`replace_encrypted_data_bytes`](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-enc/src/decrypt.rs#L1335)
normalizes empty elements and self-closing spaces with byte scans. Those scans
also change CDATA text and mistake a character-data `>` for a tag boundary.
A direct call to the backend returns the corruption before saml-rs parses it.
The same implementation is present in the 0.12.0 crate and the upstream commit
linked above, checked on 2026-11-12.

An isolated copy of bergshamra-enc 0.12.0 was changed to splice the decrypted
octets without those normalization passes, including the passes over the
surrounding document. All 20 tests in `encrypted_assertion_elements` then
passed, including the three reproductions. This is causal evidence, not an
upstream release or a completed upstream compatibility review. No dependency
patch or vendor code is included in this change.

## Standards and scope

[XML 1.0 Fifth Edition §2.4](https://www.w3.org/TR/2008/REC-xml-20081126/#syntax)
permits `>` in ordinary character data except within the forbidden `]]>`
sequence. [§2.7](https://www.w3.org/TR/2008/REC-xml-20081126/#sec-cdata-sect)
treats the contents of CDATA sections as character data. The strings inside
these test CDATA sections are text, not empty XML elements.

[SAML Core §§2.2.4, 2.3.4, and 6](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
define encrypted identifiers and assertions using XML Encryption 1.0.
[XML Encryption 1.0 §4.2 step 4](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/#sec-Processing-Decryption)
obligates bergshamra, as the decryptor of `Element` or `Content` data, to
make the original `Type` and decrypted XML character data available in UTF-8
(`MUST`). It recommends supporting replacement of `EncryptedData` with that
decrypted XML (`SHOULD`). These are normative processing requirements.
Its [§4.3.2](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/#sec-Decrypt-Replace-Imp)
describes replacement equivalent to inserting those octets and reparsing.
The replacement subsection is explicitly non-normative.

The issue's XML Encryption 1.1 §4.4 reference describes decryption, not XML
replacement. The latter is in §4.5.2 and is also non-normative.
The [approved SAML Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.pdf)
E43 key-location rules and E93 CBC integrity recommendation still apply.
Neither permits changing decrypted character data.

The dependency path is shared by decrypting roles, including the SP accepting
an encrypted assertion and the IdP reading an encrypted requested identifier.
These tests cover the SP's Web Browser SSO over HTTP-POST, not every SAML flow.
This is a text-preservation defect, with no new receiver rejection or policy
relaxation proposed.

## Implementation path

The preferred correction is upstream removal of the byte-level XML rewrites.
The current saml-rs adapter already parses the returned wrapper with
`dom::parse_with_limits` and splices the plaintext element. An upstream fix
that preserves that return shape requires only a dependency update here.

If upstream preserves the legacy document output, it can expose a separate
API for the plaintext octets before replacement. The adapter must then parse
them under its XML limits and original namespace context before splicing.
It must retain sibling `EncryptedKey` resolution, decryption-key rollover,
RSA-v1.5 policy, and signature verification over the recovered assertion.

The repository's [agent guide](../../AGENTS.md) delegates XML encryption to
bergshamra. Copying its cryptographic implementation into saml-rs would bypass
that boundary. Repairing text after decryption cannot recover the lost
information. Rewriting the peer's `Type` to trigger an opaque-data path would
depend on an undocumented backend branch. It would also discard the peer's
type information, which XML Encryption 1.0 §4.2 step 5 treats as normative.

After an upstream release, update the existing dependency, remove the three
ignores, and run these tests plus the encryption, signature, and provider
checks. There is no public API change in this preparatory stage and no
migration guide is needed.
