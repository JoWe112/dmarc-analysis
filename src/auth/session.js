'use strict';

const crypto = require('node:crypto');
const { EncryptJWT, jwtDecrypt } = require('jose');

/**
 * Stateless, encrypted session tokens (JWE, alg "dir" + A256GCM).
 *
 * The cookie value is opaque to the browser and tamper-proof: anything that
 * does not decrypt with the server key, or whose `exp` has passed, is
 * rejected. Because no server-side store is used, any replica can validate a
 * session – no sticky sessions or shared cache needed. Rotating
 * SESSION_SECRET invalidates all sessions.
 *
 * @param {string} secret  SESSION_SECRET (>= 32 characters)
 */
function createSealer(secret) {
  // Derive a fixed-length 256-bit key; the label scopes it to this purpose.
  const key = crypto.createHash('sha256').update(`dmarc-analysis/session/v1:${secret}`).digest();

  return {
    /**
     * Encrypt `payload` with an expiry `ttlSeconds` from now.
     * `purpose` is bound into the token so a login-transaction token can never
     * be replayed as a session token (and vice versa).
     */
    async seal(payload, ttlSeconds, purpose) {
      return new EncryptJWT({ ...payload, pur: purpose })
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .setIssuedAt()
        .setExpirationTime(`${Math.floor(ttlSeconds)}s`)
        .encrypt(key);
    },

    /** Decrypt and validate; returns the payload or null when invalid/expired. */
    async unseal(token, purpose) {
      if (!token) return null;
      try {
        const { payload } = await jwtDecrypt(token, key, {
          keyManagementAlgorithms: ['dir'],
          contentEncryptionAlgorithms: ['A256GCM'],
          requiredClaims: ['exp', 'iat'],
        });
        return payload.pur === purpose ? payload : null;
      } catch {
        return null;
      }
    },
  };
}

module.exports = { createSealer };
