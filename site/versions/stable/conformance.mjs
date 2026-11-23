export const pages = {
	'artifact-resolution.md': {
		title: 'Artifact resolution',
		description:
			'Rules for typed artifact resolution over SOAP: issue_artifact, answer_artifact_resolve, and resolve_artifact.',
	},
	'enhanced-client-proxy.md': {
		title: 'Enhanced Client/Proxy',
		description:
			'Typed service-provider and identity-provider ends of one Enhanced Client/Proxy login over PAOS.',
	},
	'extended-and-authority-modes.md': {
		title: 'Extended, authority, and requester modes',
		description:
			'The inventory of Conformance Requirements Tables 3 and 4 and of the attribute profiles that no table names, with one disposition for each row.',
	},
	'identifiers.md': {
		title: 'SAML-defined identifiers',
		description:
			'Attribute name formats and name identifier formats in typed Web Browser SSO: `RespondSso::attributes`, `AttributeNameFormat`, the persistent and transient `NameId` constructors, and `entity::generate_id` for message and assertion IDs.',
	},
	'identity-provider-discovery.md': {
		title: 'Identity Provider Discovery',
		description:
			'The identity provider returns the common domain cookie for the caller to write. `remember_identity_provider` is that operation. `respond_sso` does not write the cookie.',
	},
	'idp-sp-operational-modes.md': {
		title: 'IdP and SP operational modes',
		description:
			'The inventory of the IdP, IdP Lite, SP, and SP Lite columns of Conformance Requirements Table 2, and of Conformance §§3.3 to 3.7, 4, and 5, with one disposition for each obligation.',
	},
	'metadata-and-replay.md': {
		title: 'Metadata and replay',
		description:
			'Facts for metadata trust and replay on the typed browser flows. `recommended()` does not select signed metadata, invent trust anchors, or store replay. `Default`, `new`, and...',
	},
	'name-id-management.md': {
		title: 'Name identifier management',
		description:
			'Rules for typed name identifier management over SOAP at the identity provider and over HTTP-Redirect at the identity provider and the service provider.',
	},
	'single-logout.md': {
		title: 'Logout',
		description:
			'Rules for typed Single Logout: `start_slo`, `respond_slo`, and `finish_slo` on both roles. `receive_slo` reads the same request-signature field as the accept combination below....',
	},
	'web-browser-sso-acceptance.md': {
		title: 'SSO acceptance',
		description:
			'Inbound rules for typed Web Browser SSO: service-provider `finish_sso` and `accept_unsolicited_sso`, and identity-provider `receive_sso`. `SpValidationPolicy::recommended`...',
	},
	'web-browser-sso-artifact.md': {
		title: 'HTTP-Artifact response',
		description:
			'Rules for a typed Web Browser SSO response delivered as an HTTP-Artifact: respond_sso_artifact, initiate_sso_artifact, and finish_sso with BrowserInput::artifact.',
	},
	'web-browser-sso-generation.md': {
		title: 'SSO generation',
		description:
			'Producer rules for typed Web Browser SSO generation: service-provider `start_sso`, and identity-provider `respond_sso` and `initiate_sso`. `SpValidationPolicy::recommended`...',
	},
	'xml-signature-processing.md': {
		title: 'XML signature processing',
		description:
			'Reference preflight and signed-content coverage in public XML verification functions and embedded-signature flows.',
	},
	'xml-security-algorithms.md': {
		title: 'XML Signature and XML Encryption algorithms',
		description:
			'The Conformance §4 algorithms a typed identity provider and service provider sign, verify, encrypt, and decrypt with, and the `AlgorithmPolicy` defaults.',
	},
};

export const pagesOutsideRecords = {
	'../adr/0001-session-authority-logout-expiration.md': '../../explanation/logout-expiration.md',
	'../adr/0002-validation-presets.md': '../../explanation/validation-presets.md',
};
