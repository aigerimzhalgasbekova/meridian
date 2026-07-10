import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { hotp, totp, verifyTotp, generateTotpSecret, otpauthUri } from '../src/crypto/totp.js';
import { base32Decode, base32Encode } from '../src/crypto/base32.js';
import { open, seal } from '../src/crypto/secretbox.js';

const SECRET = Buffer.from('12345678901234567890', 'ascii');

describe('RFC 4226 Appendix D HOTP vectors', () => {
  const vectors = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (const [i, expected] of vectors.entries()) {
    it(`counter ${i} -> ${expected}`, () => {
      expect(hotp(SECRET, BigInt(i))).toBe(expected);
    });
  }
});

describe('RFC 6238 Appendix B TOTP vectors (SHA-1, 8 digits)', () => {
  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [time, expected] of vectors) {
    it(`T=${time} -> ${expected}`, () => {
      expect(totp(SECRET, time, 8)).toBe(expected);
    });
  }
});

describe('verifyTotp', () => {
  const t = 1_700_000_000; // arbitrary aligned-ish time

  it('accepts the current step and returns its counter', () => {
    const code = totp(SECRET, t);
    expect(verifyTotp(SECRET, code, t)).toBe(BigInt(Math.floor(t / 30)));
  });

  it('accepts one step of drift either way', () => {
    expect(verifyTotp(SECRET, totp(SECRET, t - 30), t)).not.toBeNull();
    expect(verifyTotp(SECRET, totp(SECRET, t + 30), t)).not.toBeNull();
  });

  it('rejects two steps of drift', () => {
    expect(verifyTotp(SECRET, totp(SECRET, t - 60), t)).toBeNull();
    expect(verifyTotp(SECRET, totp(SECRET, t + 60), t)).toBeNull();
  });

  it('rejects malformed codes', () => {
    expect(verifyTotp(SECRET, '12345', t)).toBeNull();
    expect(verifyTotp(SECRET, 'abcdef', t)).toBeNull();
    expect(verifyTotp(SECRET, '', t)).toBeNull();
  });
});

describe('base32', () => {
  it('round-trips generated secrets', () => {
    const { secret, base32 } = generateTotpSecret();
    expect(base32Decode(base32)).toEqual(secret);
    expect(base32Encode(base32Decode('JBSWY3DPEHPK3PXP'))).toBe('JBSWY3DPEHPK3PXP');
  });
});

describe('secretbox (TOTP secret encryption at rest)', () => {
  const key = randomBytes(32);

  it('round-trips a base32 secret through seal/open', () => {
    const { base32 } = generateTotpSecret();
    const sealed = seal(base32, key);
    expect(sealed).not.toContain(base32); // not stored in the clear
    expect(open(sealed, key)).toBe(base32);
  });

  it('produces a fresh nonce each time (distinct ciphertext for the same input)', () => {
    expect(seal('JBSWY3DPEHPK3PXP', key)).not.toBe(seal('JBSWY3DPEHPK3PXP', key));
  });

  it('rejects tampered ciphertext (GCM auth tag)', () => {
    const sealed = seal('JBSWY3DPEHPK3PXP', key);
    const bytes = Buffer.from(sealed, 'base64');
    bytes[bytes.length - 1]! ^= 0xff;
    expect(() => open(bytes.toString('base64'), key)).toThrow();
  });
});

describe('otpauth URI', () => {
  it('encodes issuer and account', () => {
    const uri = otpauthUri('ABCD1234', 'a b@example.com', 'Meridian');
    expect(uri).toBe(
      'otpauth://totp/Meridian:a%20b%40example.com?secret=ABCD1234&issuer=Meridian&algorithm=SHA1&digits=6&period=30',
    );
  });
});
