import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool, type PoolConfig } from 'pg';

import * as schema from './schema';

export type Database = NodePgDatabase<typeof schema>;

export interface DbClient {
  pool: Pool;
  db: Database;
}

export function createDbClient(url: string, extra?: PoolConfig): DbClient {
  const pool = new Pool({ connectionString: url, max: 10, ...extra });
  const db = drizzle(pool, { schema });
  return { pool, db };
}
