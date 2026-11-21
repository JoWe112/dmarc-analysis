'use strict';

const { config } = require('./config');
const { createPool, migrateWithRetry } = require('./db');
const { createApp } = require('./app');
const { createAuth } = require('./auth');

/** Process entry point: validate auth config, migrate schema, start HTTP server, handle shutdown. */
async function main() {
  // Fails fast with a list of missing/invalid OIDC_* / APP_BASE_URL / SESSION_SECRET settings.
  const auth = createAuth(config.auth);

  const pool = createPool();
  await migrateWithRetry(pool);
  console.log('[db] schema ready');

  const app = createApp({ pool, config, auth });
  const server = app.listen(config.port, () => {
    console.log(`[http] dmarc-analysis v${config.version} listening on :${config.port}`);
  });

  // Graceful shutdown so RollingUpdate does not drop in-flight requests.
  const shutdown = (signal) => {
    console.log(`[http] ${signal} received, shutting down`);
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(`[startup] fatal: ${err.code || ''} ${err.message}`);
  process.exit(1);
});
