// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import { nextBase, stableVersion } from './src/docs-version.mjs';
import { conformancePages } from './src/plugins/conformance-pages.js';
import { rewriteDocLinks } from './src/plugins/doc-links.js';
import * as nextConformance from './versions/next/conformance.mjs';
import { sidebar as nextSidebar } from './versions/next/sidebar.mjs';
import * as stableConformance from './versions/stable/conformance.mjs';
import { sidebar as stableSidebar } from './versions/stable/sidebar.mjs';

const isNext = process.env.SAML_DOCS === 'next';
const site = 'https://samlrs.vercel.app';
const base = isNext ? nextBase : '/';
const docsDir = new URL(isNext ? './src/content/docs/' : './versions/stable/docs/', import.meta.url);
const recordsDir = new URL(isNext ? '../docs/conformance/' : './versions/stable/conformance/', import.meta.url);

/** Registers the link rewriter on Astro's default Markdown processor. */
function docLinks() {
	return {
		name: 'saml-doc-links',
		hooks: {
			'astro:config:setup'({ config }) {
				config.markdown.processor?.options?.mdastPlugins?.push(rewriteDocLinks({ docsDir, base, site }));
			},
		},
	};
}

// https://astro.build/config
export default defineConfig({
	site,
	base,
	outDir: isNext ? './dist/next' : './dist',
	redirects: isNext ? {
		'/reference/conformance/xml-signature-processing':
			`${nextBase}/reference/conformance/xml-security-algorithms/#reference-and-coverage-processing`,
		'/reference/conformance/extended-and-authority-modes':
			`${nextBase}/reference/conformance/idp-sp-operational-modes/#extended-authority-and-requester-modes`,
	} : {
		'/reference/conformance/xml-schema-validation':
			`${nextBase}/reference/conformance/xml-schema-validation/`,
	},
	integrations: [
		conformancePages({ docsDir, recordsDir, ...(isNext ? nextConformance : stableConformance) }),
		starlight({
			title: 'saml-rs',
			description: 'SAML 2.0 browser SSO, metadata, and Single Logout for Rust.',
			favicon: '/favicon.svg',
			customCss: [
				'@fontsource-variable/geist',
				'@fontsource-variable/geist-mono',
				'./src/styles/custom.css',
			],
			components: {
				Hero: './src/components/Hero.astro',
				Sidebar: './src/components/Sidebar.astro',
				SiteTitle: './src/components/SiteTitle.astro',
			},
			plugins: [
				starlightLlmsTxt({
					projectName: 'saml-rs',
					description: `SAML 2.0 Service Provider and Identity Provider support for Rust. ${isNext ? 'Next documents the unreleased API on main.' : `Stable documents saml-rs v${stableVersion}.`}`,
				}),
			],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/salasebas/saml-rs' }],
			sidebar: isNext ? nextSidebar : stableSidebar,
		}),
		docLinks(),
	],
});
