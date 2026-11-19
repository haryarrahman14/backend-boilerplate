use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use super::config::Config;

#[derive(Clone)]
pub struct Mailer {
    smtp: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
    tasks: TaskTracker,
    jobs: Arc<Semaphore>,
}

const SMTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Mail jobs queued or in flight per process; beyond that a job is dropped and logged.
pub const MAX_MAIL_JOBS: usize = 1000;

impl Mailer {
    pub fn new(cfg: &Config, tasks: TaskTracker) -> Result<Self> {
        let smtp = if cfg.smtp_host.is_empty() {
            None
        } else {
            // Certificate and server name are verified whenever TLS is used.
            let params = TlsParameters::new(cfg.smtp_host.clone())?;
            let tls = match cfg.smtp_port {
                465 => Tls::Wrapper(params),
                // Production never falls back to plaintext: the send fails instead.
                _ if cfg.production => Tls::Required(params),
                // Development: STARTTLS when offered (Mailpit on 1025 does not offer it).
                _ => Tls::Opportunistic(params),
            };
            let mut builder =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
                    .port(cfg.smtp_port)
                    .tls(tls)
                    .timeout(Some(SMTP_TIMEOUT));
            if !cfg.smtp_user.is_empty() {
                builder = builder.credentials(Credentials::new(
                    cfg.smtp_user.clone(),
                    cfg.smtp_pass.clone(),
                ));
            }
            Some(builder.build())
        };
        Ok(Self {
            smtp,
            from: Mailbox::new(None, cfg.mail_from.parse::<Address>().context("MAIL_FROM")?),
            tasks,
            jobs: Arc::new(Semaphore::new(MAX_MAIL_JOBS)),
        })
    }

    /// Runs a mail job (lookup, token, send) after the response, on the shutdown-tracked task set.
    /// At most `MAX_MAIL_JOBS` at once: a job beyond that is dropped and logged, and the HTTP
    /// response does not change. Failures are only logged.
    pub fn spawn_job<F>(&self, what: &'static str, job: F)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let Ok(permit) = self.jobs.clone().try_acquire_owned() else {
            tracing::warn!(job = what, "mail queue full, job dropped");
            return;
        };
        self.tasks.spawn(
            async move {
                let _permit = permit;
                if let Err(err) = job.await {
                    // Display chain only: Debug forms of driver errors can carry row values.
                    tracing::error!(job = what, error = %format!("{err:#}"), "mail job failed");
                }
            }
            .instrument(tracing::Span::current()),
        );
    }

    /// Fire and forget: sent after the response on a background task.
    pub fn send_in_background(&self, to: String, subject: &'static str, body: String) {
        let mailer = self.clone();
        self.spawn_job("send email", async move {
            mailer.send(&to, subject, body).await
        });
    }

    pub async fn send(&self, to: &str, subject: &str, body: String) -> Result<()> {
        let Some(smtp) = &self.smtp else {
            // Development only: config refuses an empty SMTP_HOST in production, so this one
            // sanctioned token-bearing log line never reaches production logs.
            tracing::info!(
                to,
                subject,
                body,
                "SMTP_HOST is empty, logging email instead of sending"
            );
            return Ok(());
        };
        let msg = Message::builder()
            .from(self.from.clone())
            // A bare parsed Address, never a free-form string: "x<attacker@evil>" cannot become
            // a display name plus someone else's mailbox.
            .to(Mailbox::new(
                None,
                to.parse::<Address>().context("recipient address")?,
            ))
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;
        tokio::time::timeout(SMTP_TIMEOUT, smtp.send(msg))
            .await
            .context("SMTP send timed out")??;
        Ok(())
    }
}
