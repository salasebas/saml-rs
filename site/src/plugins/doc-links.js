import path from 'node:path';
import { fileURLToPath } from 'node:url';

const docsRoot = fileURLToPath(new URL('../content/docs/', import.meta.url));

/** Turn a file-relative `../page.md` link into the Starlight route. */
export function rewriteDocLinks() {
	return {
		name: 'rewrite-doc-links',
		link(node, ctx) {
			const next = toRoute(node.url, ctx.fileURL);
			if (next && next !== node.url) ctx.setProperty(node, 'url', next);
		},
	};
}

function toRoute(url, fileURL) {
	if (!fileURL || !url) return null;
	if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('/') || url.startsWith('#')) return null;

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
