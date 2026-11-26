import { access, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const indexRecord = 'README.md';
const templateRecord = 'TEMPLATE.md';
const indexPage = {
	title: 'Conformance',
	description: 'SAML conformance records by exchange and public API.',
};

export function conformancePages({ docsDir, recordsDir, codeDir, pages, pagesOutsideRecords = {} }) {
	const pagesDir = new URL('reference/conformance/', docsDir);

	async function writePage(record) {
		const source = await readFile(new URL(record, recordsDir), 'utf8');
		if (codeDir) await checkCodePaths(record, source, codeDir);
		const isIndex = record === indexRecord;
		const page = toPage(record, source, isIndex ? indexPage : pages[record], pagesOutsideRecords);
		const target = isIndex ? new URL('reference/conformance.md', docsDir) : new URL(record, pagesDir);
		await writeFile(target, page);
	}

	return {
		name: 'saml-conformance-pages',
		hooks: {
			async 'astro:config:setup'() {
				const entries = await readdir(recordsDir);
				const records = recordFiles(entries, recordsDir, pages);
				await rm(pagesDir, { recursive: true, force: true });
				await mkdir(pagesDir, { recursive: true });
				for (const record of records) await writePage(record);
				if (entries.includes(indexRecord)) await writePage(indexRecord);
			},
			'astro:server:setup'({ server, logger }) {
				const recordsPath = path.resolve(fileURLToPath(recordsDir));
				server.watcher.add(recordsPath);
				server.watcher.on('change', async (changedPath) => {
					if (path.dirname(changedPath) !== recordsPath || !changedPath.endsWith('.md')) return;
					if (path.basename(changedPath) === templateRecord) return;
					try {
						await writePage(path.basename(changedPath));
					} catch (error) {
						logger.error(error.message);
					}
				});
			},
		},
	};
}

function recordFiles(entries, recordsDir, pages) {
	const records = entries
		.filter((file) => file !== indexRecord && file !== templateRecord && file.endsWith('.md'))
		.sort();
	const unpublished = records.filter((record) => !(record in pages));
	const missing = Object.keys(pages).filter((record) => !records.includes(record));
	if (unpublished.length > 0 || missing.length > 0) {
		throw new Error(
			`Conformance pages and ${fileURLToPath(recordsDir)} differ. ` +
				`Records without a page: ${unpublished.join(', ') || 'none'}. ` +
				`Pages without a record: ${missing.join(', ') || 'none'}.`,
		);
	}
	return records;
}

async function checkCodePaths(record, source, codeDir) {
	const srcDir = new URL('src/', codeDir);
	for (const [line] of source.matchAll(/^Code:.*$/gm)) {
		const files = Array.from(line.matchAll(/`([^`]+)`/g), ([, file]) => file);
		if (files.length === 0) throw new Error(`${record} has a Code line without a path: ${line}`);
		for (const file of files) {
			const target = new URL(file, codeDir);
			if (!target.href.startsWith(srcDir.href)) {
				throw new Error(`${record} lists ${file} in a Code line, which is not under src/`);
			}
			await access(target).catch(() => {
				throw new Error(`${record} lists ${file} in a Code line, which does not exist`);
			});
		}
	}
}

function toPage(record, source, page, pagesOutsideRecords) {
	const heading = source.match(/^# .+\n\n/);
	if (!heading) throw new Error(`${record} does not start with a level-one heading`);

	const body = source
		.slice(heading[0].length)
		.replace(/\]\(([^)\s]+)\)/g, (_link, url) => `](${sitePath(record, url, pagesOutsideRecords)})`);
	if (!page) throw new Error(`${record} has no page title and description`);
	const { title, description } = page;
	return `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(description)}\n---\n\n${body}`;
}

function sitePath(record, url, pagesOutsideRecords) {
	if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('#')) return url;

	const hashAt = url.indexOf('#');
	const href = hashAt === -1 ? url : url.slice(0, hashAt);
	const hash = hashAt === -1 ? '' : url.slice(hashAt);
	if (!href.includes('/')) return record === indexRecord ? `conformance/${url}` : url;

	const page = pagesOutsideRecords[href];
	if (!page) throw new Error(`${record} links to ${href}, which has no site page`);
	return `${page}${hash}`;
}
