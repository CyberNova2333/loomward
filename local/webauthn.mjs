// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import crypto from 'node:crypto';

export function toBase64Url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

export function fromBase64Url(value) {
  if (typeof value !== 'string' || !value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid base64url value.');
  }
  return Buffer.from(value, 'base64url');
}

// Strict bounded RFC 8949 CBOR decoder covering attestationObject, COSE keys & extensions.
function decodeCborInternal(buffer, { allowTrailing = false } = {}) {
  const input = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let offset = 0;

  function readUint(additional) {
    if (additional < 24) return additional;
    if (additional === 24) {
      if (offset + 1 > input.length) throw new Error('Unexpected end of CBOR integer.');
      return input[offset++];
    }
    if (additional === 25) {
      if (offset + 2 > input.length) throw new Error('Unexpected end of CBOR integer.');
      const v = input.readUInt16BE(offset);
      offset += 2;
      return v;
    }
    if (additional === 26) {
      if (offset + 4 > input.length) throw new Error('Unexpected end of CBOR integer.');
      const v = input.readUInt32BE(offset);
      offset += 4;
      return v;
    }
    if (additional === 27) {
      if (offset + 8 > input.length) throw new Error('Unexpected end of CBOR integer.');
      const big = input.readBigUInt64BE(offset);
      offset += 8;
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR integer exceeds safe range.');
      return Number(big);
    }
    throw new Error('Indefinite-length or reserved CBOR values are not supported.');
  }

  function decodeItem(depth) {
    if (depth > 16) throw new Error('CBOR nesting depth exceeded.');
    if (offset >= input.length) throw new Error('Unexpected end of CBOR input.');
    const initial = input[offset++];
    const major = initial >> 5;
    const additional = initial & 0x1f;

    if (major === 0) return readUint(additional);
    if (major === 1) return -1 - readUint(additional);
    if (major === 2) {
      const len = readUint(additional);
      if (offset + len > input.length) throw new Error('Truncated CBOR byte string.');
      const out = input.subarray(offset, offset + len);
      offset += len;
      return Buffer.from(out);
    }
    if (major === 3) {
      const len = readUint(additional);
      if (offset + len > input.length) throw new Error('Truncated CBOR text string.');
      const out = input.subarray(offset, offset + len).toString('utf8');
      offset += len;
      return out;
    }
    if (major === 4) {
      const len = readUint(additional);
      if (len > 256) throw new Error('CBOR array too large.');
      const arr = [];
      for (let i = 0; i < len; i++) arr.push(decodeItem(depth + 1));
      return arr;
    }
    if (major === 5) {
      const len = readUint(additional);
      if (len > 256) throw new Error('CBOR map too large.');
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const key = decodeItem(depth + 1);
        const value = decodeItem(depth + 1);
        if (map.has(key)) throw new Error('Duplicate key in CBOR map.');
        map.set(key, value);
      }
      return map;
    }
    if (major === 6) {
      readUint(additional);
      return decodeItem(depth + 1);
    }
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      if (additional === 23) return undefined;
      throw new Error('Unsupported CBOR simple value.');
    }
    throw new Error('Unsupported CBOR major type.');
  }

  const result = decodeItem(0);
  if (!allowTrailing && offset !== input.length) throw new Error('Trailing bytes after CBOR object.');
  return { value: result, bytesRead: offset };
}

export function decodeCbor(buffer) {
  return decodeCborInternal(buffer, { allowTrailing: false }).value;
}

export function decodeCborPrefix(buffer) {
  return decodeCborInternal(buffer, { allowTrailing: true });
}

export function cosePublicKeyToPem(coseMap) {
  if (!(coseMap instanceof Map)) throw new Error('Invalid COSE public key.');
  const kty = coseMap.get(1);
  const alg = coseMap.get(3);

  if (kty === 2 && (alg === -7 || alg === -35)) {
    const crv = coseMap.get(-1);
    const x = coseMap.get(-2);
    const y = coseMap.get(-3);
    const expectedCrv = alg === -7 ? 1 : 2;
    const coordLen = alg === -7 ? 32 : 48;
    const crvName = alg === -7 ? 'P-256' : 'P-384';
    if (crv !== expectedCrv || !Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== coordLen || y.length !== coordLen) {
      throw new Error('Invalid EC2 COSE key parameters.');
    }
    const keyObj = crypto.createPublicKey({
      key: { kty: 'EC', crv: crvName, x: toBase64Url(x), y: toBase64Url(y) },
      format: 'jwk',
    });
    return { alg, publicKeyPem: keyObj.export({ type: 'spki', format: 'pem' }) };
  }

  if (kty === 3 && alg === -257) {
    const n = coseMap.get(-1);
    const e = coseMap.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e) || n.length < 256 || !e.length || e.length > 8) {
      throw new Error('Invalid or undersized RSA COSE key.');
    }
    const expVal = e.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    if (expVal < 3n || (expVal & 1n) === 0n) {
      throw new Error('Invalid RSA public exponent.');
    }
    const keyObj = crypto.createPublicKey({
      key: { kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e) },
      format: 'jwk',
    });
    const modBits = keyObj.asymmetricKeyDetails?.modulusLength || 0;
    if (modBits < 2048 || modBits > 8192) {
      throw new Error('RSA key modulus length must be between 2048 and 8192 bits.');
    }
    return { alg, publicKeyPem: keyObj.export({ type: 'spki', format: 'pem' }) };
  }

  if (kty === 1 && alg === -8) {
    const crv = coseMap.get(-1);
    const x = coseMap.get(-2);
    if (crv !== 6 || !Buffer.isBuffer(x) || x.length !== 32) {
      throw new Error('Invalid Ed25519 COSE key parameters.');
    }
    const keyObj = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(x) },
      format: 'jwk',
    });
    return { alg, publicKeyPem: keyObj.export({ type: 'spki', format: 'pem' }) };
  }

  throw new Error(`Unsupported WebAuthn key algorithm (kty=${String(kty)}, alg=${String(alg)}).`);
}

export function parseAuthenticatorData(authDataBytes) {
  const buf = Buffer.isBuffer(authDataBytes) ? authDataBytes : Buffer.from(authDataBytes);
  if (buf.length < 37) throw new Error('Authenticator data too short.');
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const up = (flags & 0x01) !== 0;
  const uv = (flags & 0x04) !== 0;
  const at = (flags & 0x40) !== 0;
  const ed = (flags & 0x80) !== 0;
  const signCount = buf.readUInt32BE(33);

  let offset = 37;
  let credentialId = null;
  let publicKey = null;
  if (at) {
    if (buf.length < 55) throw new Error('Attested credential data truncated.');
    const credIdLen = buf.readUInt16BE(53);
    const credEnd = 55 + credIdLen;
    if (credIdLen === 0 || credIdLen > 1023 || buf.length <= credEnd) {
      throw new Error('Invalid credential ID length.');
    }
    credentialId = buf.subarray(55, credEnd);
    const decodedKey = decodeCborPrefix(buf.subarray(credEnd));
    publicKey = cosePublicKeyToPem(decodedKey.value);
    offset = credEnd + decodedKey.bytesRead;
  }

  if (ed) {
    if (offset >= buf.length) throw new Error('Missing authenticator extension data.');
    const ext = decodeCbor(buf.subarray(offset));
    if (!(ext instanceof Map)) throw new Error('Invalid authenticator extension CBOR map.');
    offset = buf.length;
  } else if (offset !== buf.length) {
    throw new Error('Unexpected trailing bytes in authenticatorData.');
  }

  return {
    rpIdHash,
    flags,
    up,
    uv,
    at,
    ed,
    signCount,
    credentialId,
    publicKey,
  };
}

function parseAndVerifyClientData(clientDataB64, { expectedType, expectedChallenge, allowedOrigins }) {
  const clientDataBytes = fromBase64Url(clientDataB64);
  if (clientDataBytes.length > 4096) throw new Error('Client data too large.');
  const parsed = JSON.parse(clientDataBytes.toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid clientDataJSON.');
  }
  if (Boolean(parsed.crossOrigin) || parsed.topOrigin !== undefined) {
    throw new Error('Cross-origin WebAuthn requests are not permitted.');
  }
  if (parsed.type !== expectedType) {
    throw new Error(`Unexpected WebAuthn type: ${String(parsed.type)}.`);
  }
  if (parsed.challenge !== expectedChallenge) {
    throw new Error('WebAuthn challenge mismatch.');
  }
  if (typeof parsed.origin !== 'string' || !allowedOrigins.has(parsed.origin.toLowerCase())) {
    throw new Error('WebAuthn origin mismatch.');
  }
  return { clientDataBytes, clientData: parsed };
}

export function verifyRegistrationResponse({
  credential,
  expectedChallenge,
  expectedRpId = 'localhost',
  allowedOrigins,
}) {
  if (!credential || typeof credential !== 'object') throw new Error('Missing WebAuthn credential.');
  const response = credential.response;
  if (!response || typeof response !== 'object') throw new Error('Missing WebAuthn response.');

  parseAndVerifyClientData(response.clientDataJSON, {
    expectedType: 'webauthn.create',
    expectedChallenge,
    allowedOrigins,
  });

  const attestationBytes = fromBase64Url(response.attestationObject);
  if (attestationBytes.length > 32768) throw new Error('Attestation object too large.');
  const attObj = decodeCbor(attestationBytes);
  if (!(attObj instanceof Map)) throw new Error('Invalid attestationObject CBOR.');
  const authDataBytes = attObj.get('authData');
  if (!Buffer.isBuffer(authDataBytes)) throw new Error('Missing authData in attestationObject.');

  const authData = parseAuthenticatorData(authDataBytes);
  const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
  if (!crypto.timingSafeEqual(authData.rpIdHash, expectedHash)) {
    throw new Error('WebAuthn RP ID mismatch.');
  }
  if (!authData.up || !authData.uv) {
    throw new Error('PassKey registration requires User Presence and User Verification.');
  }
  if (!authData.at || !authData.credentialId || !authData.publicKey) {
    throw new Error('Missing attested credential public key.');
  }

  const credentialId = toBase64Url(authData.credentialId);
  if (typeof credential.id === 'string' && credential.id !== credentialId) {
    throw new Error('Credential ID does not match authenticatorData.');
  }

  return {
    credentialId,
    alg: authData.publicKey.alg,
    publicKeyPem: authData.publicKey.publicKeyPem,
    signCount: authData.signCount,
    transports: Array.isArray(response.transports)
      ? response.transports.filter(item => typeof item === 'string').slice(0, 8)
      : [],
  };
}

export function verifyAuthenticationResponse({
  credential,
  storedPasskey,
  expectedChallenge,
  expectedRpId = 'localhost',
  allowedOrigins,
}) {
  if (!credential || typeof credential !== 'object') throw new Error('Missing WebAuthn assertion.');
  const response = credential.response;
  if (!response || typeof response !== 'object') throw new Error('Missing WebAuthn assertion response.');

  const { clientDataBytes } = parseAndVerifyClientData(response.clientDataJSON, {
    expectedType: 'webauthn.get',
    expectedChallenge,
    allowedOrigins,
  });

  const authDataBytes = fromBase64Url(response.authenticatorData);
  if (authDataBytes.length > 16384) throw new Error('Authenticator data too large.');
  const signature = fromBase64Url(response.signature);
  if (signature.length > 2048) throw new Error('WebAuthn signature too large.');
  const authData = parseAuthenticatorData(authDataBytes);
  if (authData.at) {
    throw new Error('Attested credential data is not permitted in authentication assertions.');
  }

  const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
  if (!crypto.timingSafeEqual(authData.rpIdHash, expectedHash)) {
    throw new Error('WebAuthn RP ID mismatch.');
  }
  if (!authData.up || !authData.uv) {
    throw new Error('PassKey authentication requires User Presence and User Verification.');
  }
  if ((storedPasskey.signCount > 0 || authData.signCount > 0) && authData.signCount <= storedPasskey.signCount) {
    throw new Error('Authenticator signature counter did not advance (possible cloned key).');
  }

  const clientHash = crypto.createHash('sha256').update(clientDataBytes).digest();
  const signedPayload = Buffer.concat([authDataBytes, clientHash]);
  const keyObj = crypto.createPublicKey(storedPasskey.publicKeyPem);
  const algSpec = {
    '-7': { hash: 'sha256', keyType: 'ec', namedCurve: 'prime256v1' },
    '-35': { hash: 'sha384', keyType: 'ec', namedCurve: 'secp384r1' },
    '-257': { hash: 'sha256', keyType: 'rsa' },
    '-8': { hash: null, keyType: 'ed25519' },
  }[String(storedPasskey.alg)];
  if (!algSpec || keyObj.asymmetricKeyType !== algSpec.keyType) {
    throw new Error('Unsupported or mismatched PassKey algorithm.');
  }
  if (algSpec.namedCurve && keyObj.asymmetricKeyDetails?.namedCurve !== algSpec.namedCurve) {
    throw new Error('PassKey elliptic curve does not match declared algorithm.');
  }
  const ok = crypto.verify(algSpec.hash, signedPayload, keyObj, signature);
  if (!ok) {
    throw new Error('Invalid PassKey signature.');
  }

  return { newSignCount: authData.signCount };
}
