// Argon2id via @node-rs/argon2 (prebuilt binaries, no node-gyp).
// OWASP recommended parameters: m=19456 KiB, t=2, p=1.
import { hash, verify, Algorithm } from '@node-rs/argon2';

const PARAMS = { algorithm: Algorithm.Argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export function hashPassword(password: string): Promise<string> {
  return hash(password, PARAMS);
}

export async function verifyPassword(stored: string, password: string): Promise<boolean> {
  try {
    return await verify(stored, password, PARAMS);
  } catch {
    return false;
  }
}

// A real hash of an unguessable value, verified against unknown usernames so
// login/reset timing does not reveal whether an account exists.
let decoy: string | undefined;
export async function decoyHash(): Promise<string> {
  decoy ??= await hashPassword('decoy-' + Math.random().toString(36));
  return decoy;
}
