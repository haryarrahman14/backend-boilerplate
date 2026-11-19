"""Plain-text mail over SMTP, or to the log when SMTP_HOST is empty (development only; config enforces it)."""

import logging
from email.message import EmailMessage

import aiosmtplib

from app.platform.config import Settings

log = logging.getLogger("app.mailer")


class Mailer:
    def __init__(self, settings: Settings):
        self.s = settings

    async def send(self, to: str, subject: str, body: str) -> None:
        """`to` must already have passed the strict address check (users.schemas.is_valid_email)."""
        if not self.s.smtp_host:
            log.info("email (SMTP_HOST empty, not sent)", extra={"to": to, "subject": subject, "body": body})
            return
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = self.s.mail_from, to, subject
        message.set_content(body)
        implicit_tls = self.s.smtp_port == 465
        await aiosmtplib.send(
            message,
            hostname=self.s.smtp_host,
            port=self.s.smtp_port,
            username=self.s.smtp_user or None,
            password=self.s.smtp_pass.get_secret_value() or None,
            use_tls=implicit_tls,
            # Other ports: STARTTLS with the certificate and server name verified. Mandatory in production (the
            # send fails rather than going out in plaintext); None = use it when the server offers it (dev/Mailpit).
            start_tls=None if implicit_tls or not self.s.is_production else True,
            validate_certs=True,
            timeout=10,
        )
        log.info("email sent", extra={"to": to, "subject": subject})
