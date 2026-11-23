export const pages = {
	'artifact-resolution.md': {
		title: 'Artifact resolution',
		description:
			'Rules for typed artifact resolution over SOAP: issue_artifact, answer_artifact_resolve, and resolve_artifact.',
	},
	'identifiers.md': {
		title: 'SAML-defined identifiers',
		description:
			'Attribute name formats on `SsoAssertion::attributes`, persistent and transient `NameId` constructors, and IDs for generated messages and assertions.',
	},
	'identity-provider-discovery.md': {
		title: 'Identity Provider Discovery',
		description:
			'The identity provider returns the common domain cookie for the caller to write. `common_domain_cookie` is that operation. `respond_sso` does not write the cookie.',
	},
	'idp-sp-operational-modes.md': {
		title: 'IdP and SP operational modes',
		description:
			'The inventory of Conformance Requirements Table 2 and §§3.3 to 3.7, 4, and 5, and of Tables 3 and 4 and the attribute profiles, with one disposition for each obligation.',
	},
	'metadata-and-replay.md': {
		title: 'Metadata and replay',
		description:
			'How callers select metadata trust and replay storage for the typed browser flows.',
	},
	'name-id-management.md': {
		title: 'Name identifier management',
		description:
			'Rules for typed name identifier management over SOAP at the identity provider and over HTTP-Redirect at the identity provider and the service provider.',
	},
	'single-logout.md': {
		title: 'Logout',
		description:
			'How the service provider and identity provider send and authenticate logout requests and responses over browser bindings and SOAP.',
	},
	'web-browser-sso-acceptance.md': {
		title: 'SSO acceptance',
		description:
			'Inbound rules for typed Web Browser SSO: service-provider `finish_sso` and `accept_unsolicited_sso`, and identity-provider `receive_sso`.',
	},
	'web-browser-sso-artifact.md': {
		title: 'HTTP-Artifact response',
		description:
			'Rules for a typed Web Browser SSO response delivered as an HTTP-Artifact: respond_sso_artifact, initiate_sso_artifact, and finish_sso with Inbound::artifact.',
	},
	'web-browser-sso-generation.md': {
		title: 'SSO generation',
		description:
			'Producer rules for typed Web Browser SSO generation: service-provider `start_sso`, and identity-provider `respond_sso` and `initiate_sso`.',
	},
	'xml-schema-validation.md': {
		title: 'XML schema validation',
		description:
			'Scope of optional schema validation for received protocol XML, SOAP envelopes, decrypted documents, and metadata.',
	},
	'xml-security-algorithms.md': {
		title: 'XML Signature and XML Encryption algorithms',
		description:
			'The Conformance §4 algorithms a typed identity provider and service provider sign, verify, encrypt, and decrypt with, and the `AlgorithmPolicy` defaults.',
	},
};
