import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({
		loader: process.env.SAML_DOCS === 'next'
			? docsLoader()
			: glob({ base: './versions/stable/docs', pattern: '**/[^_]*.{md,mdx}' }),
		schema: docsSchema(),
	}),
};
