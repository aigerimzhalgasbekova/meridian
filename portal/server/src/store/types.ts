// Narrow repository interfaces. Two implementations: memory (tests + dev) and
// postgres (production, exercised by TEST_DATABASE_URL-gated integration tests).

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  /** New address awaiting verification; the old address stays active until confirmed. */
  pendingEmail: string | null;
  passwordHash: string;
  /** base32 TOTP secret — set only once verify-to-activate succeeded. */
  totpSecret: string | null;
  /** Secret generated during enrollment, not yet proven. */
  totpPendingSecret: string | null;
  /** Last accepted TOTP time-step counter (replay defense). Stored as string: exceeds 2^53. */
  totpLastCounter: string | null;
  createdAt: Date;
}

export interface Session {
  /** SHA-256 hash of the cookie value — raw session ids are never persisted. */
  idHash: string;
  userId: string;
  csrfToken: string;
  /** True after password login when TOTP is enrolled; cleared once the code is verified. */
  mfaPending: boolean;
  createdAt: Date;
  expiresAt: Date;
}

export type TokenPurpose = 'password_reset' | 'verify_email';

export interface OneTimeToken {
  id: string;
  userId: string;
  purpose: TokenPurpose;
  tokenHash: string;
  /** For verify_email: the address being verified. */
  payload: string | null;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface RecoveryCode {
  userId: string;
  codeHash: string;
  usedAt: Date | null;
}

export interface UserRepo {
  create(u: Omit<User, 'id' | 'createdAt'>): Promise<User>;
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  update(id: string, patch: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<void>;
  /**
   * Atomically advance the TOTP replay counter. Returns false (a rejected replay)
   * unless `counter` is strictly greater than the stored value — closing the
   * read-then-write TOCTOU where two concurrent codes both pass the old check.
   */
  advanceTotpCounter(id: string, counter: string): Promise<boolean>;
}

export interface SessionRepo {
  create(s: Session): Promise<void>;
  findByIdHash(idHash: string): Promise<Session | null>;
  update(idHash: string, patch: Partial<Pick<Session, 'mfaPending' | 'expiresAt'>>): Promise<void>;
  delete(idHash: string): Promise<void>;
  deleteAllForUser(userId: string): Promise<void>;
  listForUser(userId: string): Promise<Session[]>;
}

export interface TokenRepo {
  create(t: Omit<OneTimeToken, 'id' | 'createdAt' | 'usedAt'>): Promise<OneTimeToken>;
  findActiveByHash(tokenHash: string, purpose: TokenPurpose, now: Date): Promise<OneTimeToken | null>;
  /** Marks used atomically; returns false when already used (single-use enforcement). */
  markUsed(id: string, now: Date): Promise<boolean>;
  revokeAllForUser(userId: string, purpose: TokenPurpose): Promise<void>;
}

export interface RecoveryCodeRepo {
  replaceForUser(userId: string, codeHashes: string[]): Promise<void>;
  /** Consumes one unused code atomically; returns false if no match (or already used). */
  consume(userId: string, codeHash: string): Promise<boolean>;
  countUnused(userId: string): Promise<number>;
}

export interface Store {
  users: UserRepo;
  sessions: SessionRepo;
  tokens: TokenRepo;
  recoveryCodes: RecoveryCodeRepo;
  /**
   * Deletes rows that have outlived their expiry: sessions, and one-time
   * tokens (password reset / verify email) that are expired or already used.
   * Nothing reads these rows again, so unswept they only bloat the tables.
   * Returns the total number of rows removed.
   */
  sweep(now: Date): Promise<number>;
}
