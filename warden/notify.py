"""Email notifications with an hourly throttle and digest of queued messages."""
from __future__ import annotations

import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from warden import __version__
from warden.config import severity_rank

log = logging.getLogger("warden.notify")


class Mailer:
    def __init__(self, settings, db):
        self.s, self.db = settings, db

    def should_email(self, severity: str) -> bool:
        return severity_rank(severity) >= severity_rank(self.s.email_min_severity)

    def notify(self, title: str, body: str, severity: str = "medium", force: bool = False) -> str:
        """Send now if within throttle, else queue for the next digest. Returns a status string."""
        if not force and not self.should_email(severity):
            return f"not emailed (severity {severity} < EMAIL_MIN_SEVERITY {self.s.email_min_severity})"
        subject = f"[warden][{self.s.hostname}][{severity.upper()}] {title}"[:200]
        full = self._wrap(body, severity)
        if not self.s.email_configured:
            self.db.email_log(subject, severity, full, sent=False, error="email not configured")
            log.warning("email not configured; would have sent: %s", subject)
            return "email not configured (set EMAIL_TO and SMTP_HOST)"
        sent_last_hour = self.db.emails_sent_since(time.time() - 3600)
        cap = self.s.email_max_per_hour * (2 if severity == "critical" else 1)
        if not force and sent_last_hour >= cap:
            self.db.email_log(subject, severity, full, sent=False, error="queued")
            return "throttled: queued for the next digest"
        return self._send_logged(subject, severity, full)

    def flush_digest(self) -> str | None:
        queued = self.db.emails_queued()
        if not queued or not self.s.email_configured:
            return None
        if self.db.emails_sent_since(time.time() - 3600) >= self.s.email_max_per_hour:
            return None
        top = max(queued, key=lambda e: severity_rank(e["severity"]))["severity"]
        subject = f"[warden][{self.s.hostname}][{top.upper()}] digest of {len(queued)} queued reports"
        body = "\n\n".join(f"===== {e['subject']} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(e['ts']))}) =====\n{e['body']}" for e in queued)
        status = self._send_logged(subject, top, body[:200000])
        self.db.emails_mark([e["id"] for e in queued], "sent in digest" if status == "sent" else "digest failed")
        return status

    def _wrap(self, body: str, severity: str) -> str:
        return (
            f"Host: {self.s.hostname}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\nSeverity: {severity.upper()}\n\n"
            f"{body.strip()}\n\n--\nWarden {__version__} · autonomy={self.s.autonomy} · "
            f"LLM={self.s.llm.provider + '/' + self.s.llm.model if self.s.llm else 'n/a'}\n"
            f"CLI: warden status | warden incidents | journalctl -u warden\n"
        )

    def _send_logged(self, subject: str, severity: str, body: str) -> str:
        try:
            self.send_raw(subject, body)
            self.db.email_log(subject, severity, body, sent=True)
            log.info("email sent: %s", subject)
            return "sent"
        except Exception as exc:  # noqa: BLE001 — never crash the daemon over SMTP
            self.db.email_log(subject, severity, body, sent=False, error=str(exc)[:500])
            log.error("email failed: %s", exc)
            return f"email failed: {exc}"

    def send_raw(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.s.email_from
        msg["To"] = ", ".join(self.s.email_to)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=self.s.hostname)
        msg.set_content(body)
        ctx = ssl.create_default_context()
        if self.s.smtp_port == 465:
            with smtplib.SMTP_SSL(self.s.smtp_host, self.s.smtp_port, context=ctx, timeout=30) as smtp:
                self._login_send(smtp, msg)
        else:
            with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=30) as smtp:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                self._login_send(smtp, msg)

    def _login_send(self, smtp, msg) -> None:
        if self.s.smtp_user:
            smtp.login(self.s.smtp_user, self.s.smtp_password)
        smtp.send_message(msg)
