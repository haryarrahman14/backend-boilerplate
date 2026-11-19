import 'dotenv/config';
import { defineConfig } from 'prisma/config';
import { prismaCliUrl } from './src/platform/config/database-url.js';

const url = process.env.DATABASE_URL;

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: { path: 'prisma/migrations' },
  // Read lazily: `prisma generate` (e.g. in the Docker build) runs without a database. The URL's sslmode is
  // translated for Prisma's schema engine the same way the app reads it (never looser).
  datasource: { url: url ? prismaCliUrl(url) : '' },
});
