import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { stableVersion } from '../src/docs-version.mjs';

const dist = new URL('../dist/', import.meta.url);
const page = (route) => readFile(new URL(`${route}index.html`, dist), 'utf8');

async function excerpt(route) {
	const html = await page(route);
	const code = Array.from(html.matchAll(/<pre\b[^>]*>([\s\S]*?)<\/pre>/g), ([, body]) =>
		body.replace(/<[^>]*>/g, ''),
	);
	return code.join('\n');
}

test('public install and SP guide describe the published API', async () => {
	assert.match(await excerpt('start/install/'), /^cargo add saml-rs$/m);
	assert.match(await excerpt('guides/service-provider-sso/'), /Saml::sp\(/);
	assert.ok((await page('tutorial/run-the-sso-example/')).includes(`/blob/v${stableVersion}/examples/sso.rs`));
});

test('Next describes the API and installation from main', async () => {
	assert.match(await excerpt('next/start/install/'), /^cargo add saml-rs --git .* --branch main$/m);
	assert.match(await excerpt('next/guides/service-provider-sso/'), /ServiceProvider::new\(/);
	assert.ok((await page('next/guides/upgrade/')).includes('/tree/main/docs/migrations/0.8-to-0.9'));
});

test('home and guide links stay in their version', async () => {
	const guide = 'guides/service-provider-sso/';
	const record = 'reference/conformance/identifiers/';
	for (const prefix of ['', 'next/']) {
		const home = await page(prefix);
		const guideHtml = await page(`${prefix}${guide}`);
		const main = guideHtml.match(/<main\b[\s\S]*?<\/main>/)?.[0];
		assert.ok(home.includes(`href="/${prefix}start/install/"`), `Install action on /${prefix}`);
		assert.ok(home.includes(`href="/${prefix}${guide}"`), `SP guide card on /${prefix}`);
		assert.ok(main?.includes(`href="/${prefix}${record}"`), `Conformance link in /${prefix}${guide}`);
		await page(`${prefix}${record}`);
		await access(new URL(`${prefix}pagefind/pagefind.js`, dist));
	}
});

test('a guide exposes the version selector and identifies the current version', async () => {
	for (const prefix of ['', 'next/']) {
		const html = await page(`${prefix}guides/service-provider-sso/`);
		const picker = html.match(/<nav\b[^>]*aria-label="Documentation version"[^>]*>[\s\S]*?<\/nav>/)?.[0];
		assert.ok(picker, `Version selector on /${prefix}guides/service-provider-sso/`);
		assert.match(picker, /href="\/"[^>]*>v[\d.]+ \(Stable\)/);
		assert.match(picker, /href="\/next\/"[^>]*>Next \(unreleased\)/);
		assert.ok(picker.includes(`href="/${prefix}" aria-current="true"`), `Current version on /${prefix}`);
	}
});

test('public conformance URLs and Next redirects resolve', async () => {
	const old = 'reference/conformance/xml-signature-processing/';
	const replacement = 'next/reference/conformance/xml-security-algorithms/';
	assert.ok((await page(old)).includes('XML signature processing'));
	assert.ok((await page(`next/${old}`)).includes(`url=/${replacement}#reference-and-coverage-processing`));
	assert.ok((await page(replacement)).includes('id="reference-and-coverage-processing"'));
	const schema = 'reference/conformance/xml-schema-validation/';
	assert.ok((await page(schema)).includes(`url=/next/${schema}`));
	await page(`next/${schema}`);
});
