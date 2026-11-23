export const sidebar = [
	{
		label: 'Start',
		items: [
			{ label: 'Install', slug: 'start/install' },
			{ label: 'Run the example', slug: 'tutorial/run-the-sso-example' },
		],
	},
	{
		label: 'Guides',
		items: [
			{ label: 'Service provider', slug: 'guides/service-provider-sso' },
			{ label: 'Identity provider', slug: 'guides/identity-provider-sso' },
			{ label: 'Single Logout', slug: 'guides/single-logout' },
			{ label: 'Crypto provider', slug: 'guides/crypto-provider' },
			{ label: 'Validation', slug: 'guides/validation-preset' },
			{
				label: 'Upgrade',
				items: [
					{ label: 'Overview', slug: 'guides/upgrade' },
					{ label: '0.2 to 0.3', slug: 'guides/upgrade/v0-2-to-v0-3' },
					{ label: '0.3 to 0.4', slug: 'guides/upgrade/v0-3-to-v0-4' },
					{ label: '0.4 to 0.5', slug: 'guides/upgrade/v0-4-to-v0-5' },
					{ label: '0.5 to 0.6', slug: 'guides/upgrade/v0-5-to-v0-6' },
					{ label: '0.6 to 0.7', slug: 'guides/upgrade/v0-6-to-v0-7' },
					{
						label: '0.7 to 0.8',
						link: 'https://github.com/salasebas/saml-rs/blob/v0.8.0/docs/migrations/0.7-to-0.8.md',
					},
					{
						label: 'Unreleased migration',
						link: 'https://github.com/salasebas/saml-rs/tree/main/docs/migrations/0.8-to-0.9',
					},
				],
			},
		],
	},
	{
		label: 'Reference',
		items: [
			{ label: 'Coverage', slug: 'reference/coverage' },
			{ label: 'Cargo features', slug: 'reference/features' },
			{ label: 'Security', slug: 'reference/security' },
			{ label: 'Compatibility crates', slug: 'reference/compatibility-crates' },
			{
				label: 'Conformance',
				items: [
					{ label: 'How to read them', slug: 'reference/conformance' },
					{
						label: 'IdP and SP operational modes',
						slug: 'reference/conformance/idp-sp-operational-modes',
					},
					{
						label: 'SSO acceptance',
						slug: 'reference/conformance/web-browser-sso-acceptance',
					},
					{
						label: 'SSO generation',
						slug: 'reference/conformance/web-browser-sso-generation',
					},
					{ label: 'Logout', slug: 'reference/conformance/single-logout' },
					{
						label: 'Identity Provider Discovery',
						slug: 'reference/conformance/identity-provider-discovery',
					},
					{
						label: 'SAML-defined identifiers',
						slug: 'reference/conformance/identifiers',
					},
					{ label: 'Metadata and replay', slug: 'reference/conformance/metadata-and-replay' },
					{
						label: 'HTTP-Artifact response',
						slug: 'reference/conformance/web-browser-sso-artifact',
					},
					{
						label: 'Artifact resolution',
						slug: 'reference/conformance/artifact-resolution',
					},
					{
						label: 'XML schema validation',
						slug: 'reference/conformance/xml-schema-validation',
					},
					{
						label: 'Algorithms',
						slug: 'reference/conformance/xml-security-algorithms',
					},
					{
						label: 'Name identifier management',
						slug: 'reference/conformance/name-id-management',
					},
				],
			},
		],
	},
	{
		label: 'Explanation',
		items: [
			{ label: 'Validation presets', slug: 'explanation/validation-presets' },
			{ label: 'Logout expiration', slug: 'explanation/logout-expiration' },
			{ label: 'XML signatures', slug: 'explanation/xml-signature-recommendations' },
			{ label: 'Typed API', slug: 'explanation/typed-api' },
		],
	},
];
