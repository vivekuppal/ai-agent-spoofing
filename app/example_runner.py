# wiring/example_runner.py
from pathlib import Path
from typing import List
from patterns.core import XmlPatternEngine
from patterns.dmarc_patterns import BothFailPolicyPattern
from action.email_action import EmailAction

from emailsender import EmailSender

# An example of parsing a XML file while looking for patterns of spoofing


def build_engine_with_email(
    smtp_host: str, smtp_port: int, username: str, password: str, to_list: List[str]
) -> XmlPatternEngine:
    sender = EmailSender(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        username=username,
        password=password,
        use_tls=(smtp_port == 587),
        use_ssl=(smtp_port == 465),
        # optionally: DKIM config here
    )
    # open persistent conn for better throughput when scanning many files
    sender.connect()

    # Register patterns
    patterns = [
        BothFailPolicyPattern(),    # add more patterns as you go
    ]

    # Route patterns to actions
    routes = {
        "both_fail_policy": [
            EmailAction(
                sender=sender,
                from_addr=username,
                to_addrs=to_list,
                subject_prefix="[Spoofing Alert]",
            ),
            # You can add more actions here, e.g., WebhookAction(), LogAction(), QueueAction()
        ]
    }

    return XmlPatternEngine(patterns, routes)


if __name__ == "__main__":
    engine = build_engine_with_email(
        smtp_host="smtp.google.com",
        smtp_port=587,
        username="vivek@lappuai.com",
        password="",
        to_list=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
    )

    # Scan one or many XML files
    total = 0
    path = Path("c://j/noco-1.xml")
    print(f"processing file: {path}")
    total += engine.scan_file(path)
    print(f"Processed matches: {total}")
