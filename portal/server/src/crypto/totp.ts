// RFC 6238 TOTP over RFC 4226 HOTP, HMAC-SHA1, hand-rolled with node:crypto.
// Verified against RFC 6238 Appendix B test vectors (see test/totp.test.ts).
// Hand-rolled deliberately: ~40 lines of auditable stdlib crypto beats a
// dependency for a security-showcase codebase (ADR 0002).
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { base32Encode } from './base32.js';

export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** Accept the current step plus/minus one step of clock drift. */
export const TOTP_DRIFT_STEPS = 1;

export function hotp(secret: Buffer, counter: bigint, digits = TOTP_DIGITS, algorithm = 'sha1'): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const mac = createHmac(algorithm, secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const code =
    (((mac[offset]! & 0x7f) << 24) |
      ((mac[offset + 1]! & 0xff) << 16) |
      ((mac[offset + 2]! & 0xff) << 8) |
      (mac[offset + 3]! & 0xff)) %
    10 ** digits;
  return code.toString().padStart(digits, '0');
}

export function timeStep(unixSeconds: number, step = TOTP_STEP_SECONDS): bigint {
  return BigInt(Math.floor(unixSeconds / step));
}

export function totp(secret: Buffer, unixSeconds: number, digits = TOTP_DIGITS, algorithm = 'sha1', step = TOTP_STEP_SECONDS): string {
  return hotp(secret, timeStep(unixSeconds, step), digits, algorithm);
}

/**
 * Verify a submitted code within the drift window. Returns the matched time-step
 * counter (for replay defense: callers must reject counters <= last used) or
 * null when no step matches.
 */
export function verifyTotp(secret: Buffer, code: string, unixSeconds: number, drift = TOTP_DRIFT_STEPS): bigint | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = timeStep(unixSeconds);
  const submitted = Buffer.from(code);
  for (let i = -drift; i <= drift; i++) {
    const counter = current + BigInt(i);
    if (counter < 0n) continue;
    const expected = Buffer.from(hotp(secret, counter));
    if (expected.length === submitted.length && timingSafeEqual(expected, submitted)) return counter;
  }
  return null;
}

export function generateTotpSecret(): { secret: Buffer; base32: string } {
  const secret = randomBytes(20); // 160 bits, RFC 4226 recommended size
  return { secret, base32: base32Encode(secret) };
}

export function otpauthUri(base32Secret: string, accountName: string, issuer = 'Meridian'): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  return `otpauth://totp/${label}?secret=${base32Secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}
