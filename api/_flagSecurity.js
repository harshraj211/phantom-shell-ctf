import crypto from 'crypto';

const FLAG_OPEN = String.fromCharCode(70, 76, 65, 71, 123);
const FLAG_CLOSE = String.fromCharCode(125);
const TOKEN_PREFIX = 'ENC$';
const SECRET = process.env.CTF_FLAG_SECRET || 'ctf-local-dev-secret-change-this';
const KEY = crypto.createHash('sha256').update(`${SECRET}|aes-key`).digest();

export const FLAG_META = Object.freeze({
  js_source_hunter: { points: 100 },
  sql_bypass_master: { points: 300 },
  union_select_ninja: { points: 400 },
  xss_stored_pwned: { points: 300 },
  xss_reflected_gotcha: { points: 250 },
  idor_peeking_at_private_data: { points: 350 },
  path_traversal_master: { points: 400 },
});

function toBase64Url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(input) {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return Buffer.from(b64 + pad, 'base64');
}

export function buildFlag(flagKey) {
  return `${FLAG_OPEN}${flagKey}${FLAG_CLOSE}`;
}

export function encryptFlagFromKey(flagKey) {
  const flag = buildFlag(flagKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(flag, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${TOKEN_PREFIX}${toBase64Url(Buffer.concat([iv, tag, ciphertext]))}`;
}

export function normalizeSubmittedFlag(input) {
  const raw = String(input || '').trim();
  if (!raw) return null;

  if (!raw.startsWith(TOKEN_PREFIX)) {
    return raw;
  }

  try {
    const packed = fromBase64Url(raw.slice(TOKEN_PREFIX.length));
    if (packed.length <= 28) return null;
    const iv = packed.subarray(0, 12);
    const tag = packed.subarray(12, 28);
    const ciphertext = packed.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    return plaintext.trim();
  } catch {
    return null;
  }
}

export function fingerprintFlag(flag) {
  return crypto.createHash('sha256').update(`${flag}|${SECRET}|fp-v1`).digest('hex');
}
