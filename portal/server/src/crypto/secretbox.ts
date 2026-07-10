// Symmetric envelope encryption for secrets that must be recoverable (the TOTP
// secret is verified against, so it cannot be hashed like passwords/tokens).
// AES-256-GCM with a 96-bit random nonce; stored as base64(nonce||tag||ct).
// KEK comes from config (env PORTAL_TOTP_KEK). OWASP ASVS V2.8.2.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export function seal(plaintext: string, key: Buffer): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), ct]).toString('base64');
}

export function open(sealed: string, key: Buffer): string {
  const buf = Buffer.from(sealed, 'base64');
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
}
