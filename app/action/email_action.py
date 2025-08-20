# actions/email_action.py
from __future__ import annotations
from typing import List
from patterns.core import Match, Action


class EmailAction(Action):
    """
    Sends a concise alert email for a batch of matches (grouped by the engine per route invocation).
    Uses your EmailSender.
    """
    name = "email_action"

    def __init__(
        self,
        sender,                 # an instance of EmailSender (already configured & optionally connected)
        from_addr: str,
        to_addrs: list[str],
        subject_prefix: str = "[DMARC Alert]",
        use_html: bool = True,
    ):
        self.sender = sender
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.subject_prefix = subject_prefix
        self.use_html = use_html

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
        text_body = "Alerts:\n" + "\n".join(lines)

        if self.use_html:
            html_items = "".join(
                f"<li><b>{m.message}</b> — from=<code>{m.metadata.get('header_from')}</code>, "
                f"src=<code>{m.metadata.get('source_ip')}</code>, "
                f"dkim=<code>{m.metadata.get('dkim')}</code>, "
                f"spf=<code>{m.metadata.get('spf')}</code></li>"
                for m in matches
            )
            html_body = f"<h3>Alerts</h3><ul>{html_items}</ul>"
        else:
            html_body = None

        self.sender.send(
            from_addr=self.from_addr,
            to=self.to_addrs,
            subject=subject,
            text=text_body,
            html=html_body,
        )
