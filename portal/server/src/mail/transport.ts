// Email transport seam. Production would plug SES (or any SMTP relay) in
// here — same interface, one new file, no caller changes. Dev/test transport
// writes .eml-ish JSON files to an outbox directory and logs a preview URL.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface Email {
  to: string;
  subject: string;
  text: string;
}

export interface MailTransport {
  /** Must be idempotent per key: retried jobs re-send with the same key. */
  send(key: string, email: Email): Promise<void>;
}

export function outboxTransport(dir: string, log: (msg: string) => void = console.log): MailTransport {
  mkdirSync(dir, { recursive: true });
  return {
    async send(key, email) {
      // Keyed by job id: a retried job overwrites its own file, never duplicates.
      const path = join(dir, `${key}.json`);
      writeFileSync(path, JSON.stringify({ ...email, date: new Date().toISOString() }, null, 2));
      log(`[mail] ${email.subject} -> ${email.to}  preview: file://${path}`);
    },
  };
}

export function memoryTransport(): MailTransport & { sent: Map<string, Email> } {
  const sent = new Map<string, Email>();
  return {
    sent,
    async send(key, email) {
      sent.set(key, email);
    },
  };
}
