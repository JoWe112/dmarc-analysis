'use strict';

/**
 * Starts the real Express app on an ephemeral port, wired to a mock OIDC
 * provider and (optionally) a real PostgreSQL pool. Includes a tiny cookie
 * jar so tests can drive the browser login flow with fetch().
 */

const http = require('node:http');
const { createApp } = require('../../src/app');
const { createAuth } = require('../../src/auth');
const { startMockIdp } = require('./mock-idp');

const CLIENT_ID = 'dmarc-analysis';
const CLIENT_SECRET = 'test-client-secret-placeholder';

async function startHarness({ pool, config: overrides = {}, auth: authOverrides = {} } = {}) {
  const idp = await startMockIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  const server = http.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const config = {
    version: 'test', bodyLimit: '5mb', maxRecords: 100, alertThreshold: 0.1, alertTimeoutMs: 2000, alertWebhookUrl: '',
    ...overrides,
    auth: {
      issuerUrl: idp.issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, audience: '',
      scopes: 'openid profile email', requiredRole: 'dmarc-viewer', roleClaim: 'realm_access.roles',
      baseUrl: base, sessionSecret: 'x'.repeat(40), sessionTtlSeconds: 3600,
      ...authOverrides,
    },
  };
  // A stub pool is enough for auth-only tests that never reach the database.
  const app = createApp({ pool: pool || stubPool(), config, auth: createAuth(config.auth) });
  server.on('request', app);

  return {
    base,
    idp,
    config,
    jar: () => new CookieJar(),
    /** Run the full browser login flow; returns a jar holding the session cookie. */
    async login(returnTo = '/') {
      const jar = new CookieJar();
      let res = await jar.fetch(`${base}/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
      if (res.status !== 302) throw new Error(`login: ${res.status}`);
      res = await jar.fetch(res.headers.get('location')); // provider /authorize
      if (res.status !== 302) throw new Error(`authorize: ${res.status}`);
      res = await jar.fetch(res.headers.get('location')); // back to /auth/callback
      return { jar, res };
    },
    close: async () => {
      await new Promise((r) => server.close(r));
      await idp.close();
    },
  };
}

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  /** fetch without following redirects, storing Set-Cookie and sending Cookie. */
  async fetch(url, init = {}) {
    const headers = new Headers(init.headers || {});
    if (this.cookies.size) headers.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a));
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }
}

function stubPool() {
  return {
    query: async () => ({ rows: [] }),
    connect: async () => {
      throw new Error('no database in this test');
    },
  };
}

module.exports = { startHarness, CLIENT_ID };
