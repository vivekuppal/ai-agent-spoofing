# actions/email_action.py
from __future__ import annotations
from typing import List
import uuid
from app.emailsender import (EmailSender)
from app.patterns.core import Match, Action
from app.utils import (
    get_rdap_info,
    get_country_from_rdap,
    get_hostname_from_ip
)


class EmailAction(Action):
    """
    Sends a concise alert email for a batch of matches (grouped by the engine per route invocation).
    Uses EmailSender.
    """
    name = "email_action"

    def __init__(
        self,
        sender: EmailSender,
        from_addr: str,
        to_addrs: list[str],
        template_path: str,
        subject_prefix: str = "[Spoofing Alert]",
    ):
        self.sender = sender
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.subject_prefix = subject_prefix
        self.template_path = template_path

    def run(self, matches: List[Match]) -> None:
        if not matches:
            return

        subject = f'{self.subject_prefix} {matches[0].metadata.get("header_from")} {matches[0].pattern_name} x{len(matches)}'
        lines = []
        for m in matches:
            md = m.metadata
            lines.append(
                f"{m.message} | from={md.get('header_from')} src={md.get('source_ip')} "
                f"(dkim={md.get('dmarc_dkim_result')}, spf={md.get('dmarc_spf_result')})"
            )
            rdap_info = get_rdap_info(md.get("source_ip"))

            template_vars = {
                "alert_id": str(uuid.uuid4()),
                "severity": m.severity,
                "severity_color": "#dc2626",
                "environment": m.environment,
                "header_from": md.get("header_from"),
                "source_ip": md.get("source_ip"),
                "src_country": get_country_from_rdap(rdap_info),
                "spf_result": md.get("dmarc_spf_result"),
                "spf_domain": md.get("auth_spf_domain"),
                "spf_aligned": md.get("spf_aligned", False),
                "dkim_result": md.get("dmarc_dkim_result"),
                "dkim_domain": md.get("auth_dkim_domain"),
                "dkim_selector": md.get("auth_dkim_selector"),
                "dkim_aligned": md.get("dkim_aligned", False),
                "dmarc_result": md.get("dmarc_result"),
                "dmarc_disposition": md.get("dmarc_disposition"),
                "auth_dkim_pass_subdomains": md.get("dkim_pass_domains"),
                "auth_spf_pass_subdomains": md.get("spf_pass_domains"),
                "message_count": md.get("message_count"),
                "summary": "\n".join(lines),
                "xml_snippet": md.get("xml_snippet"),
                "logo_url": "https://www.lappuai.com/assets/lappu-ai-logo-final.jpg",
                "org_name": "Lappu AI",
                "hostname": get_hostname_from_ip(md.get("source_ip")),
            }

            self.sender.send(
                from_addr=self.from_addr,
                to=self.to_addrs,
                subject=subject,
                html_template_path=self.template_path,
                template_vars=template_vars
            )
            print(f"EmailAction: sent emails to {self.to_addrs}")
