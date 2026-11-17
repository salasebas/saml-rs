# Update metadata that `RequireSignature` rejects

[How to upgrade from 0.5 to 0.6](README.md)

This breaks callers that import metadata with
`MetadataTrustPolicy::RequireSignature` when the signature is not an enveloped
signature with one `#id` reference to the root, when it contains a `ds:Object`,
or when a reference transform is not enveloped-signature or exclusive
canonicalization. A root `EntitiesDescriptor` is checked the same way.

Who must change: code that imports metadata with
`MetadataTrustPolicy::RequireSignature`.

If the signature uses inclusive canonicalization, select it and leave the
other checks on:

```rust
MetadataTrustPolicy::RequireSignatureAllowingOtherCanonicalization {
    trusted_certificates: &certificates,
}
```

For any other rejected shape, sign the metadata root with an enveloped `#id`
reference and exclusive canonicalization. The accepted shapes are recorded in
[metadata trust and replay](../../conformance/metadata-and-replay.md).

An exhaustive `match` on `MetadataTrustPolicy` needs an arm for
`RequireSignatureAllowingOtherCanonicalization`. `UnsignedForCompatibility`
is unchanged.
