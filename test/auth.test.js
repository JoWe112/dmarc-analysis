'use strict';

/**
 * Authentication tests: the real app + auth module against an in-process mock
 * OIDC provider (no database needed). Covers the browser login flow, bearer
 * tokens, authorization, CSRF and open-redirect protection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { startHarness, CLIENT_ID } = require('./helpers/app-harness');
const { validateAuthConfig, rolesFromClaims, safeReturnTo } = require('../src/auth');
const { createSealer } = require('../src/auth/session');
const { parseCookies } = require('../src/auth/cookies');

test('helpers', async (t) => {
  await t.test('rolesFromClaims reads dotted paths, arrays and strings', () => {
    assert.deepEqual(rolesFromClaims({ realm_access: { roles: ['a', 'b', 3] } }, 'realm_access.roles'), ['a', 'b']);
    assert.deepEqual(rolesFromClaims({ groups: 'x y,z' }, 'groups'), ['x', 'y', 'z']);
    assert.deepEqual(rolesFromClaims({}, 'realm_access.roles'), []);
  });

  await t.test('safeReturnTo only allows local paths', () => {
    assert.equal(safeReturnTo('/?days=7'), '/?days=7');
    for (const bad of ['//evil.example', 'https://evil.example', '/\\evil.example', 'evil', '/auth/login', undefined]) {
      assert.equal(safeReturnTo(bad), '/', String(bad));
    }
  });

  await t.test('validateAuthConfig reports every problem', () => {
    assert.throws(() => validateAuthConfig({}), /OIDC_ISSUER_URL is required.*OIDC_CLIENT_ID.*OIDC_CLIENT_SECRET.*APP_BASE_URL.*SESSION_SECRET/);
    const ok = { issuerUrl: 'https://idp.example.test/realms/x', clientId: 'c', clientSecret: 's', baseUrl: 'https://dmarc.example.test', sessionSecret: 'x'.repeat(32) };
    assert.doesNotThrow(() => validateAuthConfig(ok));
    assert.doesNotThrow(() => validateAuthConfig({ ...ok, issuerUrl: 'http://keycloak.localhost:8081/realms/x' }));
    assert.throws(() => validateAuthConfig({ ...ok, issuerUrl: 'http://idp.example.test' }), /must use https/);
    assert.throws(() => validateAuthConfig({ ...ok, sessionSecret: 'short' }), /at least 32/);
    assert.throws(() => validateAuthConfig({ ...ok, baseUrl: 'https://x.example.test/sub' }), /must not contain a path/);
  });

  await t.test('sealed sessions are purpose-bound, tamper-proof and expire', async () => {
    const s = createSealer('y'.repeat(40));
    const tok = await s.seal({ sub: 'u' }, 60, 'session');
    assert.equal((await s.unseal(tok, 'session')).sub, 'u');
    assert.equal(await s.unseal(tok, 'login'), null);
    assert.equal(await s.unseal(`${tok.slice(0, -2)}AA`, 'session'), null);
    assert.equal(await createSealer('z'.repeat(40)).unseal(tok, 'session'), null);
    assert.equal(await s.unseal(await s.seal({ sub: 'u' }, -10, 'session'), 'session'), null);
  });

  await t.test('parseCookies', () => {
    assert.deepEqual({ ...parseCookies('a=1; b="x%20y"; a=2') }, { a: '1', b: 'x y' });
  });
});

test('OIDC integration (mock provider)', async (t) => {
  const h = await startHarness();
  t.after(() => h.close());
  const { base, idp } = h;

  await t.test('healthz is public', async () => {
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
  });

  await t.test('unauthenticated API calls get 401 + WWW-Authenticate', async () => {
    for (const path of ['/api/records', '/api/version', '/auth/me', '/openapi.yaml']) {
      const res = await fetch(`${base}${path}`, { headers: { accept: 'application/json' } });
      assert.equal(res.status, 401, path);
      assert.equal(res.headers.get('www-authenticate'), 'Bearer');
      assert.equal((await res.json()).error.code, 'UNAUTHENTICATED');
    }
    const post = await fetch(`${base}/api/reports`, { method: 'POST', headers: { 'content-type': 'application/xml' }, body: '<x/>' });
    assert.equal(post.status, 401);
  });

  await t.test('unauthenticated page loads redirect to login', async () => {
    const res = await fetch(`${base}/?days=7`, { headers: { accept: 'text/html' }, redirect: 'manual' });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/auth/login?returnTo=%2F%3Fdays%3D7');
  });

  await t.test('login redirect uses PKCE S256, state and nonce', async () => {
    const res = await h.jar().fetch(`${base}/auth/login`);
    const url = new URL(res.headers.get('location'));
    assert.equal(url.origin + url.pathname, `${idp.issuer}/authorize`);
    for (const p of ['state', 'nonce', 'code_challenge']) assert.ok(url.searchParams.get(p), p);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('redirect_uri'), `${base}/auth/callback`);
    assert.match(res.headers.getSetCookie()[0], /dmarc_auth_tx=.*Path=\/auth\/; HttpOnly; SameSite=Lax/);
  });

  await t.test('full browser login → session cookie → API access', async () => {
    const { jar, res } = await h.login('/?days=90');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?days=90');
    assert.ok(jar.cookies.has('dmarc_session'));
    assert.ok(!jar.cookies.has('dmarc_auth_tx'), 'login transaction cookie is cleared');

    const me = await (await jar.fetch(`${base}/auth/me`)).json();
    assert.deepEqual(me, { sub: 'user-1', name: 'Test Analyst', username: 'analyst', email: 'analyst@example.test', roles: ['dmarc-viewer'] });
    assert.equal((await jar.fetch(`${base}/api/records?days=all`)).status, 200);
    assert.equal((await jar.fetch(`${base}/`, { headers: { accept: 'text/html' } })).status, 200);
  });

  await t.test('callback without a login transaction is rejected', async () => {
    const res = await fetch(`${base}/auth/callback?code=x&state=y`);
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, 'LOGIN_EXPIRED');
  });

  await t.test('a tampered state fails the login', async () => {
    const jar = h.jar();
    let res = await jar.fetch(`${base}/auth/login`);
    res = await jar.fetch(res.headers.get('location'));
    const cb = new URL(res.headers.get('location'));
    cb.searchParams.set('state', 'forged');
    res = await jar.fetch(cb.href);
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error.code, 'LOGIN_FAILED');
    assert.ok(!jar.cookies.has('dmarc_session'));
  });

  await t.test('open redirects via returnTo are neutralised', async () => {
    const { res } = await h.login('//evil.example/phish');
    assert.equal(res.headers.get('location'), '/');
  });

  await t.test('users without the required role are refused at login', async () => {
    idp.state.user = { ...idp.state.user, sub: 'user-2', roles: ['something-else'] };
    try {
      const { jar, res } = await h.login();
      assert.equal(res.status, 403);
      assert.equal((await res.json()).error.code, 'FORBIDDEN');
      assert.ok(!jar.cookies.has('dmarc_session'));
    } finally {
      idp.state.user = { ...idp.state.user, sub: 'user-1', roles: ['dmarc-viewer'] };
    }
  });

  await t.test('CSRF: cookie-authenticated POSTs must be same-origin', async () => {
    const { jar } = await h.login();
    const post = (headers) => jar.fetch(`${base}/api/reports`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{}' });
    assert.equal((await post({})).status, 403, 'no Origin');
    assert.equal((await post({ origin: 'https://evil.example' })).status, 403, 'foreign Origin');
    assert.equal((await post({ 'sec-fetch-site': 'cross-site' })).status, 403);
    const same = await post({ origin: base });
    assert.equal(same.status, 400, 'passes auth, then fails body validation');
    assert.equal((await same.json()).error.code, 'VALIDATION_FAILED');
  });

  await t.test('bearer access tokens', async () => {
    const call = (token) => fetch(`${base}/api/records?days=all`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal((await call(await idp.issueAccessToken())).status, 200, 'valid');
    // Bearer requests are not subject to the cookie CSRF check.
    const post = await fetch(`${base}/api/reports`, { method: 'POST', headers: { authorization: `Bearer ${await idp.issueAccessToken()}`, 'content-type': 'application/json' }, body: '{}' });
    assert.equal(post.status, 400);

    const cases = {
      'other client (azp)': await idp.issueAccessToken(undefined, { azp: 'someone-else' }),
      'expired': await idp.issueAccessToken(undefined, {}, { expiresIn: '-5m' }),
      'ID token as bearer': await idp.issueAccessToken(undefined, { typ: 'ID' }),
      'wrong issuer': await idp.issueAccessToken(undefined, { iss: 'https://other.example.test' }),
      'forged signature': await idp.forge({ sub: 'user-1' }),
      'garbage': 'not-a-jwt',
    };
    for (const [name, tok] of Object.entries(cases)) {
      const res = await call(tok);
      assert.equal(res.status, 401, name);
      assert.equal((await res.json()).error.code, 'INVALID_TOKEN', name);
    }
    const noRole = await call(await idp.issueAccessToken({ ...idp.state.user, roles: [] }));
    assert.equal(noRole.status, 403);
  });

  await t.test('logout clears the session and returns the end-session URL', async () => {
    const { jar } = await h.login();
    assert.equal((await jar.fetch(`${base}/auth/logout`, { method: 'POST' })).status, 403, 'needs same-origin');
    const res = await jar.fetch(`${base}/auth/logout`, { method: 'POST', headers: { origin: base } });
    assert.equal(res.status, 200);
    const { redirect } = await res.json();
    const u = new URL(redirect);
    assert.equal(u.origin + u.pathname, `${idp.issuer}/logout`);
    assert.equal(u.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(u.searchParams.get('post_logout_redirect_uri'), `${base}/`);
    assert.ok(!jar.cookies.has('dmarc_session'));
    assert.equal((await jar.fetch(`${base}/api/records`)).status, 401);
  });
});

test('audience mode: aud must contain OIDC_AUDIENCE', async (t) => {
  const h = await startHarness({ auth: { audience: 'dmarc-api' } });
  t.after(() => h.close());
  const call = async (tok) => (await fetch(`${h.base}/api/records`, { headers: { authorization: `Bearer ${tok}` } })).status;
  assert.equal(await call(await h.idp.issueAccessToken(undefined, { aud: ['account', 'dmarc-api'], azp: 'cli' })), 200);
  assert.equal(await call(await h.idp.issueAccessToken(undefined, { aud: 'account' })), 401);
});

test('identity provider down → 503', async (t) => {
  const h = await startHarness();
  t.after(() => h.close());
  await h.idp.close();
  const res = await fetch(`${h.base}/auth/login`);
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error.code, 'IDENTITY_PROVIDER_UNAVAILABLE');
});
