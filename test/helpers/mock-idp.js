'use strict';

/**
 * A tiny in-process OpenID Connect provider for integration tests.
 *
 * Implements just enough of OIDC for the authorization-code + PKCE flow:
 * discovery, /authorize (auto-approves the configured user), /token (checks
 * client credentials, code, redirect_uri and the PKCE verifier), JWKS and an
 * end-session endpoint. Tokens are real RS256 JWTs, so the app's verification
 * code runs unmodified.
 */

const http = require('node:http');
const crypto = require('node:crypto');
const jose = require('jose');

async function startMockIdp({ clientId, clientSecret }) {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await jose.exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const state = {
    // The user that /authorize signs in; tests mutate this.
    user: { sub: 'user-1', name: 'Test Analyst', preferred_username: 'analyst', email: 'analyst@example.test', roles: ['dmarc-viewer'] },
    tokenRequests: 0,
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, issuer);
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    try {
      if (url.pathname === '/.well-known/openid-configuration') {
        return json(200, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          end_session_endpoint: `${issuer}/logout`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        });
      }
      if (url.pathname === '/jwks') return json(200, { keys: [jwk] });

      if (url.pathname === '/authorize') {
        const p = url.searchParams;
        if (p.get('client_id') !== clientId || p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256') {
          return json(400, { error: 'invalid_request' });
        }
        const code = crypto.randomBytes(16).toString('hex');
        codes.set(code, {
          redirectUri: p.get('redirect_uri'),
          challenge: p.get('code_challenge'),
          nonce: p.get('nonce'),
          user: { ...state.user },
        });
        const back = new URL(p.get('redirect_uri'));
        back.searchParams.set('code', code);
        back.searchParams.set('state', p.get('state'));
        back.searchParams.set('iss', issuer);
        res.writeHead(302, { location: back.href });
        return res.end();
      }

      if (url.pathname === '/token' && req.method === 'POST') {
        state.tokenRequests++;
        const body = new URLSearchParams(await readBody(req));
        const [id, secret] = basicAuth(req) || [body.get('client_id'), body.get('client_secret')];
        if (id !== clientId || secret !== clientSecret) return json(401, { error: 'invalid_client' });
        const entry = codes.get(body.get('code'));
        codes.delete(body.get('code')); // single use
        if (!entry || entry.redirectUri !== body.get('redirect_uri')) return json(400, { error: 'invalid_grant' });
        const challenge = crypto.createHash('sha256').update(body.get('code_verifier') || '').digest('base64url');
        if (challenge !== entry.challenge) return json(400, { error: 'invalid_grant', error_description: 'PKCE' });
        return json(200, {
          token_type: 'Bearer',
          expires_in: 300,
          access_token: await issueAccessToken(entry.user),
          id_token: await sign({
            sub: entry.user.sub, aud: clientId, azp: clientId, nonce: entry.nonce, typ: 'ID',
            name: entry.user.name, preferred_username: entry.user.preferred_username, email: entry.user.email,
          }),
        });
      }

      if (url.pathname === '/logout') return json(200, { loggedOut: true });
      json(404, { error: 'not_found' });
    } catch (err) {
      json(500, { error: 'server_error', message: err.message });
    }
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const issuer = `http://127.0.0.1:${server.address().port}`;

  async function sign(claims, { expiresIn = '5m', header = {} } = {}) {
    return new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'JWT', ...header })
      .setIssuer(claims.iss || issuer)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(privateKey);
  }

  /** Keycloak-shaped access token; `overrides` lets tests craft bad tokens. */
  function issueAccessToken(user = state.user, overrides = {}, opts = {}) {
    return sign(
      {
        sub: user.sub, azp: clientId, aud: 'account', typ: 'Bearer', scope: 'openid profile email',
        preferred_username: user.preferred_username, email: user.email, name: user.name,
        realm_access: { roles: user.roles },
        ...overrides,
      },
      opts,
    );
  }

  return {
    issuer,
    state,
    issueAccessToken,
    sign,
    /** Sign with a key the provider does not publish (forged token). */
    async forge(claims) {
      const { privateKey: other } = await jose.generateKeyPair('RS256');
      return new jose.SignJWT({ azp: clientId, typ: 'Bearer', ...claims })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
        .setIssuer(issuer).setIssuedAt().setExpirationTime('5m').sign(other);
    },
    close: () => new Promise((r) => server.close(r)),
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => resolve(b));
    req.on('error', reject);
  });
}

function basicAuth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return null;
  const [id, secret] = Buffer.from(h.slice(6), 'base64').toString().split(':');
  return [decodeURIComponent(id), decodeURIComponent(secret)];
}

module.exports = { startMockIdp };
