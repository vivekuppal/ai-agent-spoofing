# actions/email_action.py
from __future__ import annotations
from typing import List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.emailsender import (EmailSender)
from app.patterns.core import Match, Action
from app.feature_utils import is_subfeature_enabled_for_customer


class FeatureGatedEmailAction(Action):
    """
    Sends a concise alert email for a batch of matches (grouped by the engine per route invocation).
    Sending of alerts is gated by a subfeature flag per customer.
    Uses EmailSender.
    """

    name = "feature_gated_email_action"

    def __init__(
        self,
        *,
        sender: EmailSender,
        from_addr: str,
        to_addrs: list[str],
        subject_prefix: str,
        template_path: str,
        subfeature_key: str,            # e.g. "SPOOFING_ALERT_EMAIL" | "MISCONFIGURATION_ALERT_EMAIL"
        fail_open: bool = False,        # if customer_id missing: send (True) or skip (False)
    ):
        self.sender = sender
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.subject_prefix = subject_prefix
        self.template_path = template_path
        self.subfeature_key = subfeature_key
        self.fail_open = fail_open
        self._buffer: List[Match] = []
        self._ctx: dict[str, Any] | None = None

    def set_context(self, ctx: dict[str, Any]) -> None:  # <-- NEW
        self._ctx = ctx

    # sync per Action interface
    def run(self, matches: List[Match]) -> None:
        if matches:
            self._buffer.extend(matches)

    async def flush(self, session: AsyncSession) -> int:
        """
        Returns number of emails actually sent.
        """
        sent = 0
        for m in self._buffer:
            md = m.metadata or {}
            if self._ctx and "customer_id" in self._ctx and "flags" in self._ctx:
                customer_id = self._ctx["customer_id"]
                flags: dict[str, bool] = self._ctx["flags"]
                enabled = bool(flags.get(self.subfeature_key, False))
            else:
                # fallback (rare): use DB
                customer_id = md.get("customer_id")
                if customer_id is None and not self.fail_open:
                    continue
                enabled = await is_subfeature_enabled_for_customer(
                    session,
                    customer_id=customer_id,
                    feature_key=self.subfeature_key,
                    respect_is_active=True
                )

            if customer_id is None:
                if not self.fail_open:
                    continue  # skip silently
            else:
                enabled = await is_subfeature_enabled_for_customer(
                    session,
                    customer_id=customer_id,
                    feature_key=self.subfeature_key,
                    respect_is_active=True,
                )
                if not enabled:
                    continue

            # Build subject/vars exactly like your EmailAction
            subject = f'{self.subject_prefix} {md.get("header_from")} {m.pattern_name}'
            template_vars = {
                "alert_id": md.get("alert_id"),
                "severity": m.severity,
                "severity_color": "#dc2626" if (m.severity or "").lower() in {"high","critical"} else "#f59e0b",
                "environment": m.environment,
                "header_from": md.get("header_from"),
                "source_ip": md.get("source_ip"),
                "src_country": md.get("src_country"),
                "spf_result": md.get("dmarc_spf_result"),
                "spf_domain": md.get("auth_spf_domain"),
                "spf_aligned": md.get("spf_aligned", False),
                "dkim_result": md.get("dmarc_dkim_result"),
                "dkim_domain": md.get("auth_dkim_domain"),
                "dkim_selector": md.get("auth_dkim_selector"),
                "dkim_aligned": md.get("dkim_aligned", False),
                "dmarc_result": md.get("dmarc_result", "fail"),
                "dmarc_disposition": md.get("dmarc_disposition"),
                "auth_dkim_pass_subdomains": md.get("auth_dkim_pass_subdomains") or md.get("dkim_pass_domains"),
                "auth_spf_pass_subdomains": md.get("auth_spf_pass_subdomains") or md.get("spf_pass_domains"),
                "message_count": md.get("message_count"),
                "summary": md.get("summary"),
                "xml_snippet": md.get("xml_snippet"),
                "logo_url": "https://www.lappuai.com/assets/lappu-ai-logo-final.jpg",
                "org_name": "Lappu AI",
                "hostname": md.get("hostname"),
                "policy_p": md.get("policy_p"),
            }

            self.sender.send(
                from_addr=self.from_addr,
                to=self.to_addrs,
                subject=subject,
                html_template_path=self.template_path,
                template_vars=template_vars,
            )
            sent += 1

        self._buffer.clear()
        return sent
