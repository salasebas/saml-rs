import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function conformancePages({ docsDir, recordsDir, pages, pagesOutsideRecords = {} }) {
	const pagesDir = new URL('reference/conformance/', docsDir);

	async function writePage(record) {
		const source = await readFile(new URL(record, recordsDir), 'utf8');
		const page = toPage(record, source, pages[record], pagesOutsideRecords);
		await writeFile(new URL(record, pagesDir), page);
	}

	return {
		name: 'saml-conformance-pages',
		hooks: {
			async 'astro:config:setup'() {
				const records = await recordFiles(recordsDir, pages);
				await rm(pagesDir, { recursive: true, force: true });
				await mkdir(pagesDir, { recursive: true });
				for (const record of records) await writePage(record);
			},
			'astro:server:setup'({ server, logger }) {
				const recordsPath = path.resolve(fileURLToPath(recordsDir));
				server.watcher.add(recordsPath);
				server.watcher.on('change', async (changedPath) => {
					if (path.dirname(changedPath) !== recordsPath || !changedPath.endsWith('.md')) return;
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

async function recordFiles(recordsDir, pages) {
	const records = (await readdir(recordsDir)).filter((file) => file.endsWith('.md')).sort();
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
	if (!href.includes('/')) return url;

	const page = pagesOutsideRecords[href];
	if (!page) throw new Error(`${record} links to ${href}, which has no site page`);
	return `${page}${hash}`;
}
