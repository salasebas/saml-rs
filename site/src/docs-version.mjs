export const stableVersion = '0.8.0';
export const nextBase = '/next';

export function docsPath(base, href) {
	return href.startsWith('/') && !href.startsWith('//') ? `${base.replace(/\/$/, '')}${href}` : href;
}
