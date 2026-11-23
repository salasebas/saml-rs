import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { docsPath } from '../docs-version.mjs';

/** Turn a file-relative `../page.md` link into the Starlight route. */
export function rewriteDocLinks({ docsDir, base }) {
	const docsRoot = fileURLToPath(docsDir);
	return {
		name: 'rewrite-doc-links',
		link(node, ctx) {
			const route = toRoute(node.url, ctx.fileURL, docsRoot);
			if (route) ctx.setProperty(node, 'url', docsPath(base, route));
		},
	};
}

function toRoute(url, fileURL, docsRoot) {
	if (!fileURL || !url) return null;
	if (url.startsWith('/')) return url;
	if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('#')) return null;

	const hashAt = url.indexOf('#');
	const href = hashAt === -1 ? url : url.slice(0, hashAt);
	const hash = hashAt === -1 ? '' : url.slice(hashAt);
	if (!href.endsWith('.md') && !href.endsWith('.mdx')) return null;

	const target = path.resolve(path.dirname(fileURLToPath(fileURL)), href);
	let rel = path.relative(docsRoot, target).split(path.sep).join('/');
	if (rel.startsWith('..')) return null;

	rel = rel.replace(/\.mdx?$/, '');
	if (rel === 'index') return `/${hash}`;
	if (rel.endsWith('/index')) rel = rel.slice(0, -'/index'.length);
	return `/${rel}/${hash}`;
}
