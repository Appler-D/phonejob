// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import {
  createCipheriv,
  createECDH,
  createPrivateKey,
  hkdfSync,
  randomBytes,
  sign as signWithKey,
} from 'node:crypto';

const RECORD_SIZE = 4096;
const MAX_PAYLOAD_BYTES = 3800;
const DEFAULT_SUBJECT = 'mailto:phonejob@localhost';

function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function decodeBase64Url(value, name) {
  if (typeof value !== 'string' || !value) throw new Error(`${name} is invalid`);
  return Buffer.from(value, 'base64url');
}

export function buildVapidAuthorization({
  privateJwk,
  publicKey,
  endpoint,
  subject = DEFAULT_SUBJECT,
  now = Date.now(),
}) {
  const audience = new URL(endpoint).origin;
  const header = base64Url(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const claims = base64Url(
    JSON.stringify({
      aud: audience,
      exp: Math.floor(now / 1000) + 12 * 60 * 60,
      sub: subject,
    }),
  );
  const unsigned = `${header}.${claims}`;
  const key = createPrivateKey({ key: privateJwk, format: 'jwk' });
  const signature = signWithKey('sha256', Buffer.from(unsigned), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return `vapid t=${unsigned}.${base64Url(signature)}, k=${publicKey}`;
}

export function encryptPushPayload(keys, payload) {
  const uaPublic = decodeBase64Url(keys?.p256dh, 'p256dh');
  const authSecret = decodeBase64Url(keys?.auth, 'auth');
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04) throw new Error('p256dh is invalid');
  if (authSecret.length !== 16) throw new Error('auth is invalid');
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  if (data.length > MAX_PAYLOAD_BYTES) throw new Error('push payload is too large');

  const ephemeral = createECDH('prime256v1');
  ephemeral.generateKeys();
  const asPublic = ephemeral.getPublicKey();
  const shared = ephemeral.computeSecret(uaPublic);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', shared, authSecret, keyInfo, 32));
  const salt = randomBytes(16);
  const cek = Buffer.from(
    hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16),
  );
  const nonce = Buffer.from(
    hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12),
  );

  const plaintext = Buffer.concat([data, Buffer.from([0x02])]);
  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const header = Buffer.alloc(16 + 4 + 1 + asPublic.length);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(asPublic.length, 20);
  asPublic.copy(header, 21);
  return Buffer.concat([header, ciphertext]);
}

export async function sendPush({
  subscription,
  vapid,
  payload,
  fetchImpl = globalThis.fetch,
  now = Date.now(),
  ttl = 3600,
  urgency = 'normal',
  subject = DEFAULT_SUBJECT,
}) {
  if (!subscription?.endpoint || !subscription.keys) throw new Error('push subscription is invalid');
  if (typeof fetchImpl !== 'function') throw new Error('fetch is unavailable');
  const endpoint = new URL(subscription.endpoint);
  if (endpoint.protocol !== 'https:') throw new Error('push endpoint must be https');
  const body = encryptPushPayload(subscription.keys, payload);
  const response = await fetchImpl(subscription.endpoint, {
    method: 'POST',
    headers: {
      Authorization: buildVapidAuthorization({
        privateJwk: vapid.privateJwk,
        publicKey: vapid.publicKey,
        endpoint: subscription.endpoint,
        subject,
        now,
      }),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      TTL: String(ttl),
      Urgency: urgency,
    },
    body,
  });
  return { ok: response.ok, status: response.status };
}
