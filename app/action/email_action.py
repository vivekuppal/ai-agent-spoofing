# actions/email_action.py
from __future__ import annotations
from typing import List
import uuid
from app.patterns.core import Match, Action
from app.utils import (
    get_rdap_info,
    get_country_from_rdap
)


class EmailAction(Action):
    """
    Sends a concise alert email for a batch of matches (grouped by the engine per route invocation).
    Uses your EmailSender.
    """
    name = "email_action"

    def __init__(
        self,
        sender,
        from_addr: str,
        to_addrs: list[str],
        subject_prefix: str = "[Spoofing Alert]",
    ):
        self.sender = sender
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.subject_prefix = subject_prefix

    def run(self, matches: List[Match]) -> None:
        if not matches:
            return

        subject = f"{self.subject_prefix} {matches[0].pattern_name} x{len(matches)}"
        # Keep it simple; swap with Jinja later if you want rich templates
        lines = []
        for m in matches:
            md = m.metadata
            lines.append(
                f"- {m.message} | from={md.get('header_from')} src={md.get('source_ip')} "
                f"(dkim={md.get('dkim')}, spf={md.get('spf')})"
            )
            template_vars: dict[str, str] = {}
            rdap_info = get_rdap_info(m.metadata.get("source_ip"))
            template_vars["alert_id"] = str(uuid.uuid4())
            template_vars["severity"] = m.severity
            template_vars["severity_color"] = "#dc2626"
            template_vars["environment"] = m.environment
            template_vars["header_from"] = md.get("header_from")
            template_vars["source_ip"] = md.get("source_ip")
            template_vars["src_country"] = get_country_from_rdap(rdap_info)
            template_vars["spf_result"] = md.get("dmarc_spf_result")
            template_vars["spf_domain"] = md.get("auth_spf_domain")
            template_vars["spf_aligned"] = md.get("spf_aligned", False)
            template_vars["dkim_result"] = md.get("dmarc_dkim_result")
            template_vars["dkim_domain"] = md.get("auth_dkim_domain")
            template_vars["dkim_selector"] = md.get("auth_dkim_selector")
            template_vars["dkim_aligned"] = md.get("dkim_aligned", False)
            template_vars["dmarc_result"] = md.get("dmarc_result")
            template_vars["dmarc_disposition"] = md.get("dmarc_disposition")
            template_vars["message_count"] = len(matches)
            template_vars["xml_snippet"] = "\n".join(lines)
            template_vars["triage_url"] = f"https://example.com/triage/{m.pattern_name}"
            template_vars["logo_url"] = "https://www.lappuai.com/assets/lappu-ai-logo-final.jpg"
            template_vars["org_name"] = "Lappu AI"

            # Google map URL
            # https://www.google.com/maps/@LATITUDE,LONGITUDE,ZOOM_LEVELz

            result = self.sender.send(
                from_addr=self.from_addr,
                to=self.to_addrs,
                subject=subject,
                html_template_path="app/templates/spoofing-alert.html",
                template_vars=template_vars
            )
            print(f"EmailAction: sent {result} emails to {self.to_addrs}")
