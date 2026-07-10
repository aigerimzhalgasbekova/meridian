import type { JobHandler } from '../queue/worker.js';
import type { MailTransport } from '../mail/transport.js';

export const SEND_EMAIL = 'send_email';

export interface SendEmailPayload {
  to: string;
  subject: string;
  text: string;
  [key: string]: unknown;
}

/** Idempotent: the transport is keyed by job id, so retries never double-send. */
export function jobHandlers(mail: MailTransport): Record<string, JobHandler> {
  return {
    [SEND_EMAIL]: async (job) => {
      const p = job.payload as unknown as SendEmailPayload;
      await mail.send(job.id, { to: p.to, subject: p.subject, text: p.text });
    },
  };
}
