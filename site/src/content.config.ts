import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const projects = defineCollection({
  loader: glob({ pattern: '*.md', base: './src/content/projects' }),
  schema: z.object({
    name: z.string(), // directory name in the monorepo
    title: z.string(),
    pitch: z.string(), // one-line card pitch
    challenge: z.string(), // the architectural challenge it demonstrates
    tech: z.array(z.string()),
    order: z.number(),
  }),
});

const guide = defineCollection({
  loader: glob({ pattern: '*.md', base: './src/content/guide' }),
  schema: z.object({
    title: z.string(),
    chapter: z.number(),
    summary: z.string(),
  }),
});

export const collections = { projects, guide };
