# app/processor.py
from __future__ import annotations
import hashlib
import traceback
from typing import Any, Dict
from app.patterns.core import XmlPatternEngine
from app.patterns.dmarc_patterns import BothFailPolicyPattern
from app.patterns.dmarc_strict_alignment_misconfig import StrictAlignmentMisconfigurationPattern
from app.emailsender import EmailSender
from app.action.alert_action import AlertInsertAction
from app.action.feature_gated_email_action import FeatureGatedEmailAction


async def process_file(content: bytes, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a DMARC XML file content (bytes), applying patterns
    and executing actions."""
    try:
        file_hash = hashlib.sha256(content).hexdigest()
        print(f"Processing file with SHA256: {file_hash}")
        async_session = context["async_session"]
        email_sender: EmailSender = context["email_sender"]

        patterns = [
            StrictAlignmentMisconfigurationPattern(
                file_hash=file_hash,
                fall_through=False,
                db=async_session),
            BothFailPolicyPattern(
                file_hash=file_hash,
                fall_through=True,
                db=async_session),
        ]

        misconfig_email = FeatureGatedEmailAction(
            sender=email_sender,
            from_addr="from_addr=vivek@lappuai.com",
            to_addrs=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
            subject_prefix="[Misconfiguration Alert]",
            template_path="app/templates/domain-misconfiguration-alert.html",
            subfeature_key="MISCONFIGURATION_ALERT_EMAIL",
            fail_open=False,
        )
        spoof_email = FeatureGatedEmailAction(
            sender=email_sender,
            from_addr="vivek@lappuai.com",
            to_addrs=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
            subject_prefix="[Spoofing Alert]",
            template_path="app/templates/spoofing-alert.html",
            subfeature_key="SPOOFING_ALERT_EMAIL",
            fail_open=False,
        )

        alert_action = AlertInsertAction(default_status="open")

        routes = {
            StrictAlignmentMisconfigurationPattern.name: [
                misconfig_email,
                alert_action,
            ],
            BothFailPolicyPattern.name: [
                spoof_email,
                alert_action,
            ],
        }

        engine = XmlPatternEngine(patterns, routes)
        matches_count = await engine.scan_string_async(content.decode("utf-8"))

        # Async flush with feature gating
        sent_misconfig = await misconfig_email.flush(async_session)
        sent_spoof = await spoof_email.flush(async_session)
        inserted = await alert_action.flush(async_session)

        return {
            "matches_count": matches_count,
            "emails_sent": sent_misconfig + sent_spoof,
            "alerts_inserted": inserted,
        }
    except Exception as ex:
        print(f"Error processing file: {ex}")
        print(traceback.print_exc())
        return {"kind": "bytes", "size": len(content)}
