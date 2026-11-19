import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import nodemailer from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport/index.js';
import type { Env } from '../config/env.validation.js';
import { requestContext } from '../logging/request-context.js';
import { safeError } from '../logging/safe-error.js';
import { resolveSmtpHost } from './smtp-host.js';

export interface Mail {
  to: string;
  subject: string;
  text: string;
}

const SMTP_TIMEOUT_MS = 10_000;
const MAX_IN_FLIGHT = 1_000;

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private readonly smtp?: SMTPTransport.Options & { host: string };
  private readonly from: string;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(config: ConfigService<Env, true>) {
    this.from = config.get('MAIL_FROM', { infer: true });
    const host = config.get('SMTP_HOST', { infer: true });
    if (host) {
      const user = config.get('SMTP_USER', { infer: true });
      const port = config.get('SMTP_PORT', { infer: true });
      const production = config.get('APP_ENV', { infer: true }) === 'production';
      // SPEC 2: 465 → implicit TLS; otherwise STARTTLS, mandatory in production (the send fails instead of
      // falling back to plaintext) and opportunistic in development. Certificates and host name are verified.
      this.smtp = {
        host,
        port,
        secure: port === 465,
        requireTLS: port !== 465 && production,
        tls: { servername: host, rejectUnauthorized: true },
        connectionTimeout: SMTP_TIMEOUT_MS,
        greetingTimeout: SMTP_TIMEOUT_MS,
        socketTimeout: SMTP_TIMEOUT_MS,
        auth: user ? { user, pass: config.get('SMTP_PASS', { infer: true }) } : undefined,
      };
    }
  }

  /**
   * Fire-and-forget (SPEC 4): runs after the handler returns, never fails the request, failures are logged.
   * `build` may do DB work too, so the response time does not depend on whether the account exists.
   */
  sendInBackground(label: string, build: () => Promise<Mail | null>): void {
    if (this.inFlight.size >= MAX_IN_FLIGHT) {
      // Known ceiling: no durable queue. Under a flood we drop (and log) rather than grow without bound.
      this.logger.error({ msg: `background mail dropped, ${MAX_IN_FLIGHT} already in flight: ${label}` });
      return;
    }
    const ctx = requestContext.getStore();
    const job = new Promise<void>((resolve) => setImmediate(resolve))
      .then(() => requestContext.run(ctx ?? { requestId: 'background' }, async () => {
        const mail = await build();
        if (mail) await this.send(mail);
      }))
      .catch((err: unknown) => {
        const detail = safeError(err);
        this.logger.error({ msg: `background mail failed: ${label}`, error: detail instanceof Error ? detail.message : detail });
      })
      .finally(() => this.inFlight.delete(job));
    this.inFlight.add(job);
  }

  private async send(mail: Mail): Promise<void> {
    if (!this.smtp) {
      // Dev-only path (SPEC 2): startup refuses APP_ENV=production without SMTP_HOST, so this log, which holds
      // the one-time link, never happens in production.
      this.logger.log({ msg: 'email (SMTP_HOST empty, not sent)', to: mail.to, subject: mail.subject, body: mail.text });
      return;
    }
    // We resolve SMTP_HOST ourselves (see smtp-host.ts) and connect by IP; TLS still verifies SMTP_HOST's name.
    const addresses = await resolveSmtpHost(this.smtp.host, SMTP_TIMEOUT_MS);
    let lastError: unknown;
    for (const address of addresses) {
      // One short-lived transport per mail; nothing is pooled, so nothing is held between sends.
      const transport = nodemailer.createTransport({ ...this.smtp, host: address, servername: this.smtp.host });
      try {
        await transport.sendMail({ from: this.from, ...mail });
        this.logger.log({ msg: 'email sent', subject: mail.subject });
        return;
      } catch (err) {
        lastError = err;
        // Only "could not connect" moves on to the next address; anything later might mean it was half-sent.
        if ((err as { code?: unknown }).code !== 'ECONNECTION') throw err;
      } finally {
        transport.close();
      }
    }
    throw lastError;
  }

  /** Graceful shutdown (main.ts): let queued mails finish, bounded, after HTTP has drained and before the DB pool closes. */
  async drain() {
    await Promise.race([Promise.allSettled([...this.inFlight]), new Promise((r) => setTimeout(r, 10_000).unref())]);
  }
}
