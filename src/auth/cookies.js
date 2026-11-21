'use strict';

/**
 * Minimal cookie helpers (avoids a cookie-parser dependency).
 */

/** Parse a Cookie request header into a plain object. First occurrence wins. */
function parseCookies(header) {
  const out = Object.create(null);
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    if (!name || name in out) continue;
    let value = part.slice(idx + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

/**
 * Serialise a Set-Cookie value. Always HttpOnly; SameSite defaults to Lax so
 * the cookie is sent on top-level navigations (needed for the OIDC callback)
 * but not on cross-site subrequests or POSTs.
 */
function serializeCookie(name, value, { maxAge, path = '/', secure = false, sameSite = 'Lax' } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, 'HttpOnly', `SameSite=${sameSite}`];
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

/** Append a Set-Cookie header without clobbering ones already set. */
function appendCookie(res, cookie) {
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, cookie) : [cookie]);
}

module.exports = { parseCookies, serializeCookie, appendCookie };
