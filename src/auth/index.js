'use strict';

/**
 * Built-in OpenID Connect authentication.
 *
 *  Browser:  /auth/login → provider (authorization code + PKCE) → /auth/callback
 *            → encrypted session cookie (stateless, works across replicas).
 *  API:      either that session cookie, or `Authorization: Bearer <access token>`
 *            (a JWT verified against the provider's JWKS, issuer and audience/azp).
 *  Authz:    optional OIDC_REQUIRED_ROLE checked in OIDC_ROLE_CLAIM.
 *  CSRF:     cookie-authenticated unsafe requests must come from APP_BASE_URL's origin.
 */

const express = require('express');
const oidc = require('openid-client');
const jose = require('jose');
const { createSealer } = require('./session');
const { parseCookies, serializeCookie, appendCookie } = require('./cookies');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const TX_TTL_SECONDS = 600; // a login attempt must complete within 10 minutes
const ACCEPTED_JWS_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

/** Error carrying an HTTP status and an error-envelope code. */
class AuthError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** http:// issuers are only accepted for loopback hosts (local development and tests). */
function isLoopbackHost(hostname) {
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '[::1]';
}

/** Read a dotted claim path (e.g. "realm_access.roles") as an array of strings. */
function rolesFromClaims(claims, path) {
  let v = claims;
  for (const key of path.split('.')) {
    if (v === null || typeof v !== 'object') return [];
    v = v[key];
  }
  if (Array.isArray(v)) return v.filter((x) => typeof x === 'string');
  if (typeof v === 'string') return v.split(/[\s,]+/).filter(Boolean);
  return [];
}

/**
 * Only allow same-site relative paths as post-login targets (prevents open
 * redirects such as "//evil.example" or "https://evil.example").
 */
function safeReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (value.startsWith('/auth/')) return '/';
  return value.length > 2048 ? '/' : value;
}

/**
 * Validate the auth section of the config. Throws listing every problem so a
 * misconfigured pod fails fast at startup instead of at first login.
 */
function validateAuthConfig(a) {
  const problems = [];
  for (const [k, env] of [
    ['issuerUrl', 'OIDC_ISSUER_URL'],
    ['clientId', 'OIDC_CLIENT_ID'],
    ['clientSecret', 'OIDC_CLIENT_SECRET'],
    ['baseUrl', 'APP_BASE_URL'],
    ['sessionSecret', 'SESSION_SECRET'],
  ]) {
    if (!a[k]) problems.push(`${env} is required`);
  }
  if (a.sessionSecret && a.sessionSecret.length < 32) problems.push('SESSION_SECRET must be at least 32 characters');
  for (const [k, env] of [['issuerUrl', 'OIDC_ISSUER_URL'], ['baseUrl', 'APP_BASE_URL']]) {
    if (!a[k]) continue;
    let u;
    try {
      u = new URL(a[k]);
    } catch {
      problems.push(`${env} must be an absolute URL`);
      continue;
    }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopbackHost(u.hostname))) {
      problems.push(`${env} must use https (http is only allowed for localhost)`);
    }
    // The app's routes are mounted at "/", so it must be served at the root of its host.
    if (k === 'baseUrl' && u.pathname !== '/') problems.push('APP_BASE_URL must not contain a path (serve the app at "/")');
  }
  if (problems.length) throw new Error(`Invalid authentication configuration: ${problems.join('; ')}`);
}

/**
 * Create the auth component.
 * @param {object} a  config.auth (see src/config.js)
 * @returns {{ router: import('express').Router, requireAuth: Function, verifyAccessToken: Function }}
 */
function createAuth(a) {
  validateAuthConfig(a);
  const baseUrl = new URL(a.baseUrl);
  const baseOrigin = baseUrl.origin;
  const redirectUri = `${baseOrigin}/auth/callback`;
  const postLogoutRedirectUri = `${baseOrigin}/`;
  const secure = baseUrl.protocol === 'https:';
  // __Host- cookies must be Secure, Path=/ and host-only: the strongest scoping browsers offer.
  const SESSION_COOKIE = secure ? '__Host-dmarc_session' : 'dmarc_session';
  const TX_COOKIE = secure ? '__Secure-dmarc_auth_tx' : 'dmarc_auth_tx';
  const TX_PATH = '/auth/';
  const sealer = createSealer(a.sessionSecret);
  const issuer = new URL(a.issuerUrl);

  /* ---------- Provider discovery (lazy, cached, retried after failure) ---------- */

  let configPromise = null;
  let jwks = null;

  function getProvider() {
    if (!configPromise) {
      const options = { timeout: 10 };
      if (issuer.protocol === 'http:') options.execute = [oidc.allowInsecureRequests];
      configPromise = oidc
        .discovery(issuer, a.clientId, a.clientSecret, undefined, options)
        .then((config) => {
          jwks = jose.createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri), {
            timeoutDuration: 5000,
            cooldownDuration: 30000,
          });
          return config;
        })
        .catch((err) => {
          configPromise = null; // retry on the next request
          console.error(`[auth] OIDC discovery failed: ${err.code || err.name}`);
          throw new AuthError(503, 'IDENTITY_PROVIDER_UNAVAILABLE', 'The identity provider is not reachable.');
        });
    }
    return configPromise;
  }

  /* ---------- Token verification ---------- */

  /**
   * Verify an access token (JWT) and return the user it represents.
   * Audience rule: if OIDC_AUDIENCE is set, `aud` must contain it; otherwise
   * the token must have been issued to this client (`azp` == OIDC_CLIENT_ID).
   * ID tokens and refresh tokens are rejected.
   */
  async function verifyAccessToken(token) {
    const config = await getProvider();
    let payload;
    let header;
    try {
      ({ payload, protectedHeader: header } = await jose.jwtVerify(token, jwks, {
        issuer: config.serverMetadata().issuer,
        algorithms: ACCEPTED_JWS_ALGS,
        requiredClaims: ['exp', 'sub'],
        clockTolerance: 30,
      }));
    } catch (err) {
      if (err instanceof jose.errors.JWKSTimeout) {
        throw new AuthError(503, 'IDENTITY_PROVIDER_UNAVAILABLE', 'The identity provider is not reachable.');
      }
      throw new AuthError(401, 'INVALID_TOKEN', 'The access token is invalid or expired.');
    }
    if (header.typ && !['JWT', 'at+jwt', 'application/at+jwt'].includes(header.typ)) {
      throw new AuthError(401, 'INVALID_TOKEN', 'The token is not an access token.');
    }
    if (['ID', 'Refresh', 'Logout'].includes(payload.typ)) {
      throw new AuthError(401, 'INVALID_TOKEN', 'The token is not an access token.');
    }
    if (a.audience) {
      const aud = [].concat(payload.aud || []);
      if (!aud.includes(a.audience)) throw new AuthError(401, 'INVALID_TOKEN', 'The token audience is not accepted.');
    } else if (payload.azp !== a.clientId) {
      throw new AuthError(401, 'INVALID_TOKEN', 'The token was not issued to this application.');
    }
    return userFromClaims(payload);
  }

  function userFromClaims(claims, roleSource = claims) {
    return {
      sub: String(claims.sub),
      name: str(claims.name),
      username: str(claims.preferred_username),
      email: str(claims.email),
      roles: rolesFromClaims(roleSource, a.roleClaim),
    };
  }

  function assertAuthorized(user) {
    if (a.requiredRole && !user.roles.includes(a.requiredRole)) {
      throw new AuthError(403, 'FORBIDDEN', 'You do not have access to this application.');
    }
  }

  /* ---------- Middleware ---------- */

  /**
   * Authenticate every request it is mounted in front of. Sets `req.user`.
   * Unauthenticated browser page loads are redirected to the login flow;
   * everything else gets 401 JSON.
   */
  async function requireAuth(req, res, next) {
    try {
      const authz = req.get('authorization') || '';
      if (/^bearer\s+/i.test(authz)) {
        const user = await verifyAccessToken(authz.replace(/^bearer\s+/i, '').trim());
        assertAuthorized(user);
        req.user = user;
        req.authMethod = 'bearer';
        return next();
      }

      const session = await sealer.unseal(parseCookies(req.headers.cookie)[SESSION_COOKIE], 'session');
      if (session) {
        // CSRF defence for cookie auth: unsafe requests must be same-origin.
        if (!SAFE_METHODS.has(req.method) && !isSameOrigin(req)) {
          throw new AuthError(403, 'CSRF_REJECTED', 'Cross-origin request rejected.');
        }
        req.user = { sub: session.sub, name: session.name, username: session.username, email: session.email, roles: session.roles || [] };
        req.authMethod = 'session';
        return next();
      }

      if (req.method === 'GET' && !req.path.startsWith('/api/') && req.accepts(['html', 'json']) === 'html') {
        return res.redirect(302, `${TX_PATH}login?returnTo=${encodeURIComponent(req.originalUrl)}`);
      }
      res.set('WWW-Authenticate', 'Bearer');
      throw new AuthError(401, 'UNAUTHENTICATED', 'Authentication is required.');
    } catch (err) {
      next(err);
    }
  }

  /**
   * Same-origin check: the Origin header (sent by browsers on POST) must equal
   * APP_BASE_URL's origin. Fall back to Sec-Fetch-Site; a request with
   * neither is rejected.
   */
  function isSameOrigin(req) {
    const origin = req.get('origin');
    if (origin) return origin === baseOrigin;
    const site = req.get('sec-fetch-site');
    return site === 'same-origin';
  }

  /* ---------- Routes: /auth/* ---------- */

  const router = express.Router();

  /** Start the authorization-code flow with PKCE, state and nonce. */
  router.get('/login', async (req, res, next) => {
    try {
      const config = await getProvider();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const tx = await sealer.seal(
        { v: codeVerifier, s: state, n: nonce, r: safeReturnTo(req.query.returnTo) },
        TX_TTL_SECONDS,
        'login',
      );
      appendCookie(res, serializeCookie(TX_COOKIE, tx, { maxAge: TX_TTL_SECONDS, path: TX_PATH, secure }));
      const url = oidc.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri,
        scope: a.scopes,
        code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: 'S256',
        state,
        nonce,
      });
      res.set('Cache-Control', 'no-store').redirect(302, url.href);
    } catch (err) {
      next(err);
    }
  });

  /** Complete the flow: exchange the code, verify tokens, issue the session cookie. */
  router.get('/callback', async (req, res, next) => {
    try {
      const tx = await sealer.unseal(parseCookies(req.headers.cookie)[TX_COOKIE], 'login');
      // The login transaction is single-use: clear it whatever the outcome.
      appendCookie(res, serializeCookie(TX_COOKIE, '', { maxAge: 0, path: TX_PATH, secure }));
      if (!tx) throw new AuthError(400, 'LOGIN_EXPIRED', 'The login attempt expired or is invalid. Please sign in again.');

      const config = await getProvider();
      // Rebuild the callback URL from APP_BASE_URL (not Host headers) so it matches redirect_uri exactly.
      const currentUrl = new URL(redirectUri);
      const q = req.originalUrl.indexOf('?');
      currentUrl.search = q >= 0 ? req.originalUrl.slice(q) : '';

      let tokens;
      try {
        tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
          pkceCodeVerifier: tx.v,
          expectedState: tx.s,
          expectedNonce: tx.n,
          idTokenExpected: true,
        });
      } catch (err) {
        console.warn(`[auth] login failed: ${err.code || err.name}${err.error ? ` (${err.error})` : ''}`);
        throw new AuthError(401, 'LOGIN_FAILED', 'Sign-in failed.');
      }

      // Identity from the ID token; roles from the (verified) access token,
      // where providers such as Keycloak put them by default.
      const idClaims = tokens.claims();
      const fromAccess = await verifyAccessToken(tokens.access_token);
      if (fromAccess.sub !== String(idClaims.sub)) throw new AuthError(401, 'LOGIN_FAILED', 'Sign-in failed.');
      const user = { ...userFromClaims(idClaims), roles: fromAccess.roles };
      assertAuthorized(user);

      const session = await sealer.seal(user, a.sessionTtlSeconds, 'session');
      appendCookie(res, serializeCookie(SESSION_COOKIE, session, { maxAge: a.sessionTtlSeconds, secure }));
      console.log(`[auth] login sub=${user.sub}`);
      res.set('Cache-Control', 'no-store').redirect(302, tx.r);
    } catch (err) {
      next(err);
    }
  });

  /** Current user (requires authentication). */
  router.get('/me', requireAuth, (req, res) => {
    const { sub, name, username, email, roles } = req.user;
    res.set('Cache-Control', 'no-store').json({ sub, name, username, email, roles });
  });

  /**
   * Log out: clear the session cookie and return the provider's end-session
   * URL for the browser to navigate to (RP-initiated logout). POST + same-origin
   * check so other sites cannot log users out.
   */
  router.post('/logout', requireAuth, async (req, res, next) => {
    try {
      appendCookie(res, serializeCookie(SESSION_COOKIE, '', { maxAge: 0, secure }));
      let redirect = postLogoutRedirectUri;
      try {
        const config = await getProvider();
        if (config.serverMetadata().end_session_endpoint) {
          redirect = oidc.buildEndSessionUrl(config, {
            client_id: a.clientId,
            post_logout_redirect_uri: postLogoutRedirectUri,
          }).href;
        }
      } catch {
        // Provider unreachable: the local session is still cleared.
      }
      res.set('Cache-Control', 'no-store').json({ redirect });
    } catch (err) {
      next(err);
    }
  });

  return { router, requireAuth, verifyAccessToken, AuthError };
}

function str(v) {
  return typeof v === 'string' ? v : '';
}

module.exports = { createAuth, validateAuthConfig, rolesFromClaims, safeReturnTo, AuthError };
