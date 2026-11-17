# Metadata element order research

## Scope

Before order validation, `elements_order` silently ignored unknown names, emitted a configured group more than once when its name repeated, and omitted configured groups absent from the order. The relevant question is how to validate this generation option without claiming more SAML conformance than the code provides.

## OASIS requirements

The OASIS Metadata 2.0 schema uses `xs:sequence` for role children. A role descriptor orders `Signature`, `Extensions`, zero or more `KeyDescriptor`, optional `Organization`, and zero or more `ContactPerson`. `SSODescriptorType` then orders zero or more `ArtifactResolutionService`, `SingleLogoutService`, `ManageNameIDService`, and `NameIDFormat`. The IdP type follows with one or more `SingleSignOnService`, then optional `NameIDMappingService`, `AssertionIDRequestService`, `AttributeProfile`, and SAML `Attribute`. The SP type follows with one or more `AssertionConsumerService`, then optional `AttributeConsumingService`. These schema sequences define child order for schema-valid metadata. [OASIS Metadata 2.0 §§2.4.1–2.4.4](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)

The schema allows multiple `KeyDescriptor` elements and multiple endpoints in their respective groups. Approved Errata 05 E68 explicitly says that multiple same-purpose keys may all be used and that a relying party SHOULD allow any of them. Therefore, rejecting duplicate *group names* in the local `elements_order` option does not reject multiple keys or endpoints; those are values within one group. E69 leaves the meaning and processing of `ds:KeyInfo` content to the relying party. [Approved Errata 05 E68–E69](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html)

`Organization` and `ContactPerson` are legal both on `EntityDescriptor` (§2.3.2) and on `RoleDescriptorType` (§2.4.1). Rejecting these names from the current role-order option can be justified only by this generator's configuration scope: it does not generate role-level organization or contact values. Do not describe them as entity-only under the standard. The entity schema also places `Organization`, then `ContactPerson`, after its role descriptors. [OASIS Metadata 2.0 §§2.3.2, 2.4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)

## Implementation comparison

At pinned commit [`tngan/samlify` `c460f60`](https://github.com/tngan/samlify/tree/c460f60a5fb6f78bc919d6b1b5476c74a6afce06), both [`metadata-sp.ts`](https://github.com/tngan/samlify/blob/c460f60a5fb6f78bc919d6b1b5476c74a6afce06/src/metadata-sp.ts#L150-L155) and [`metadata-idp.ts`](https://github.com/tngan/samlify/blob/c460f60a5fb6f78bc919d6b1b5476c74a6afce06/src/metadata-idp.ts#L122-L127) accept a caller-provided order. Each builds a map of configured groups and emits only populated groups found in the order. Thus omitted groups disappear and unknown names produce no output. Repeated names remain in the filtered list, so the generator emits that configured group again. The SP map includes an empty `AttributeConsumingService` group, so that token is recognized but emits nothing when no such service is configured. The code documents that the default IdP order mirrors its historical sequence. This is precedent for preserving explicit order as a compatibility behavior, not proof that every custom order validates against the schema.

At pinned [`crewjam/saml` `7dcc89e`](https://github.com/crewjam/saml/blob/7dcc89e61df7bb076974abf55fda0947cd6c44d0/metadata.go#L375-L388), Go metadata structs model repeated groups as slices, including `KeyDescriptors`, `ContactPeople`, `SingleLogoutServices`, `AssertionConsumerServices`, and `AttributeConsumingServices`. The declared fields follow the schema sequence across embedded role, SSO, and concrete IdP/SP structs. This provides a fixed-order model that preserves group multiplicity, rather than a caller-selected order.

## Guidance

Validate group tokens at `build()`: reject duplicate names and names the role generator does not support. Emit configured groups omitted from the option so configuration cannot silently disappear; place additions according to the schema's group sequence while retaining the relative order of explicit tokens. Preserve existing explicit orders, including any that are not schema-valid, as compatibility behavior. Do not claim that generated metadata is globally schema-conformant when callers choose an order outside the schema sequence. The SP `AttributeConsumingService` token can remain a recognized no-op when no corresponding configuration exists; it is part of the SP schema even if this generation path has no values for it.

Duplicate group tokens are a local API policy. The schema allows repeated elements within several groups. Rejecting repeated token names prevents the API from writing a whole configured group twice; it does not impose a one-key or one-endpoint limit.
