'use strict';

/**
 * Central runtime configuration, read once from environment variables.
 *
 * Database connection: either DATABASE_URL, or the standard libpq variables
 * PGHOST / PGPORT / PGDATABASE / PGUSER / PGPASSWORD / PGSSLMODE (these are
 * picked up natively by `pg` when DATABASE_URL is not set).
 */

const pkg = require('../package.json');

/** Parse an integer env var with a fallback and lower bound. */
function intEnv(name, fallback, min = 0) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < min) {
    throw new Error(`Environment variable ${name} must be an integer >= ${min}`);
  }
  return n;
}

/** Parse a float env var with a fallback. */
function floatEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n)) throw new Error(`Environment variable ${name} must be a number`);
  return n;
}

/**
 * Map PGSSLMODE to a node-postgres `ssl` option. node-postgres only honours
 * sslmode when it is embedded in a connection string, so we translate it here
 * for the PG* variable path.
 */
function sslFromMode(mode) {
  switch ((mode || '').toLowerCase()) {
    case '':
    case 'disable':
      return false;
    case 'allow':
    case 'prefer':
    case 'require':
    case 'no-verify':
      // Encrypt but do not verify the server certificate.
      return { rejectUnauthorized: false };
    case 'verify-ca':
    case 'verify-full':
      return { rejectUnauthorized: true };
    default:
      throw new Error(`Unsupported PGSSLMODE: ${mode}`);
  }
}

const config = {
  version: pkg.version,
  port: intEnv('PORT', 8080, 1),
  // Max accepted request body (raw XML payloads can be large).
  bodyLimit: process.env.BODY_LIMIT || '20mb',
  databaseUrl: process.env.DATABASE_URL || '',
  pgSsl: sslFromMode(process.env.PGSSLMODE),
  pgPoolMax: intEnv('PG_POOL_MAX', 10, 1),
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  // Alert when the failed share of newly inserted mail exceeds this ratio (0.10 = 10 %).
  alertThreshold: floatEnv('ALERT_THRESHOLD', 0.1),
  alertTimeoutMs: intEnv('ALERT_TIMEOUT_MS', 5000, 100),
  // Hard cap on rows returned by GET /api/records.
  maxRecords: intEnv('MAX_RECORDS', 5000, 1),

  // Built-in OpenID Connect authentication (validated in src/auth/index.js).
  auth: {
    issuerUrl: process.env.OIDC_ISSUER_URL || '',
    clientId: process.env.OIDC_CLIENT_ID || '',
    clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    // Optional: required `aud` value for bearer tokens. Unset → `azp` must equal the client ID.
    audience: process.env.OIDC_AUDIENCE || '',
    scopes: process.env.OIDC_SCOPES || 'openid profile email',
    // Optional: users must have this role/group. Empty → any authenticated user.
    requiredRole: process.env.OIDC_REQUIRED_ROLE || '',
    // Dotted claim path holding roles/groups (Keycloak realm roles by default).
    roleClaim: process.env.OIDC_ROLE_CLAIM || 'realm_access.roles',
    // Public URL of this app; redirect URI = APP_BASE_URL + /auth/callback.
    baseUrl: process.env.APP_BASE_URL || '',
    sessionSecret: process.env.SESSION_SECRET || '',
    sessionTtlSeconds: intEnv('SESSION_TTL_SECONDS', 28800, 60),
  },
};

module.exports = { config, sslFromMode };
