import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { docsPath, nextBase } from '../docs-version.mjs';

export function rewriteDocLinks({ docsDir, base, site }) {
	const docsRoot = fileURLToPath(docsDir);
	return {
		name: 'rewrite-doc-links',
		link(node, ctx) {
			const route = toRoute(node.url, ctx.fileURL, docsRoot, site);
			if (!route) return;
			const [pathname] = route.split(/[?#]/, 1);
			const href = pathname === nextBase || pathname.startsWith(`${nextBase}/`) ? route : docsPath(base, route);
			ctx.setProperty(node, 'url', href);
		},
	};
}

function toRoute(url, fileURL, docsRoot, site) {
	if (!fileURL || !url) return null;
	if (url.startsWith('/')) return url;
	const absolute = URL.parse(url);
	if (absolute) return absolute.origin === site ? `${absolute.pathname}${absolute.search}${absolute.hash}` : null;
	if (url.startsWith('#')) return null;

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
