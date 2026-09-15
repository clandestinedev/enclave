import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';

const url = process.env.DATABASE_URL ?? 'postgres://enclave:enclave_dev@localhost:5432/enclave_dev';

async function run() {
  const pool = new Pool({ connectionString: url });
  const db = drizzle(pool);
  await migrate(db, { migrationsFolder: new URL('../../migrations', import.meta.url).pathname });
  console.log(`[enclave] migrations applied against ${url}`);
  await pool.end();
}

run().catch((err) => {
  console.error('[enclave] migration failed:', err);
  process.exit(1);
});
