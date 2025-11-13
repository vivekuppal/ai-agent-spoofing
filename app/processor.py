# app/processor.py
from __future__ import annotations
import hashlib
import traceback
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.patterns.core import XmlPatternEngine
from app.patterns.dmarc_patterns import BothFailPolicyPattern
from app.patterns.dmarc_strict_alignment_misconfig import StrictAlignmentMisconfigurationPattern
from app.emailsender import EmailSender
from app.action.alert_action import AlertInsertAction
from app.action.feature_gated_email_action import FeatureGatedEmailAction
from app.feature_utils import is_subfeature_enabled_for_customer, is_feature_enabled_for_customer


async def is_file_processed(session: AsyncSession,
                            file_hash: str) -> bool:
    """
    Given a file_hash, resolve the associated customer_id from the database."""
    sql = text("""
      SELECT id
      FROM processed_file pf
      WHERE pf.file_hash=:fh AND pf.status='done'
      LIMIT 1
    """)
    row = (await session.execute(sql, {"fh": file_hash})).first()
    return True if row else False


async def _resolve_customer_id(session: AsyncSession,
                               file_hash: str) -> int | None:
    """
    Given a file_hash, resolve the associated customer_id from the database."""
    sql = text("""
      SELECT dr.customer_id
      FROM processed_file pf
      JOIN dmarc_reports dr ON dr.id = pf.dmarc_report_id
      WHERE pf.file_hash=:fh AND pf.status='done'
      LIMIT 1
    """)
    row = (await session.execute(sql, {"fh": file_hash})).first()
    return row._mapping["customer_id"] if row else None


async def _load_flags(session, customer_id: int) -> dict[str, bool]:
    subfeature_keys = [
      "SPOOFING_ALERT_EMAIL", "MISCONFIGURATION_ALERT_EMAIL",
      "SPOOFING_ALERT", "MISCONFIGURATION_ALERT"
    ]
    feature_keys = [
        'ALERTS', 'EMAILS'
    ]
    results = {}
    for k in subfeature_keys:
        results[k] = await is_subfeature_enabled_for_customer(
            session, customer_id=customer_id,
            feature_key=k, respect_is_active=True
        )
    for k in feature_keys:
        results[k] = await is_feature_enabled_for_customer(
            session, customer_id=customer_id,
            feature_key=k, respect_is_active=True
        )
    return results


async def process_file(content: bytes, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a DMARC XML file content (bytes), applying patterns
    and executing actions."""
    try:
        file_hash = hashlib.sha256(content).hexdigest()
        print(f"Processing file with SHA256: {file_hash}")
        if not await is_file_processed(context["async_session"], file_hash):
            print('File has not been processed by dmarc processor. Skipping..')
            return {"kind": "bytes", "size": len(content)}

        async_session = context["async_session"]
        customer_id = await _resolve_customer_id(async_session, file_hash)
        flags = await _load_flags(async_session, customer_id)
        # print(f"Customer ID: {customer_id}, Feature Flags: {flags}")

        need_spoof = flags["SPOOFING_ALERT_EMAIL"] or flags["SPOOFING_ALERT"] or flags["ALERTS"] or flags["EMAILS"]
        need_mis = flags["MISCONFIGURATION_ALERT_EMAIL"] or flags["MISCONFIGURATION_ALERT"] or flags["ALERTS"] or flags["EMAILS"]

        # Early exit: nothing enabled → no XML scan at all
        if (not need_spoof and not need_mis) or customer_id is None:
            print("No features enabled or customer ID not found; skipping processing.")
            return {"matches_count": 0, "emails_sent": 0, "alerts_inserted": 0, "skipped": "features disabled"}

        email_sender: EmailSender = context["email_sender"]
        # Build only the patterns we actually need
        patterns = []
        if need_mis:
            patterns.append(StrictAlignmentMisconfigurationPattern(
                file_hash=file_hash,
                fall_through=False,
                # Pass DB only if DB work will be used (alert enabled). Saves one SELECT per record otherwise.
                db=async_session if flags["MISCONFIGURATION_ALERT"] else None
            ))
        if need_spoof:
            patterns.append(BothFailPolicyPattern(
                file_hash=file_hash,
                fall_through=True,
                db=async_session if flags["SPOOFING_ALERT"] else None
            ))

        ctx = {"customer_id": customer_id, "flags": flags}

        misconfig_email = FeatureGatedEmailAction(
            sender=email_sender,
            from_addr="from_addr=vivek@lappuai.com",
            to_addrs=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
            subject_prefix="[Misconfiguration Alert]",
            template_path="app/templates/domain-misconfiguration-alert.html",
            subfeature_key="MISCONFIGURATION_ALERT_EMAIL",
            feature_key="EMAILS",
            fail_open=False,
        )
        spoof_email = FeatureGatedEmailAction(
            sender=email_sender,
            from_addr="vivek@lappuai.com",
            to_addrs=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
            subject_prefix="[Spoofing Alert]",
            template_path="app/templates/spoofing-alert.html",
            subfeature_key="SPOOFING_ALERT_EMAIL",
            feature_key="EMAILS",
            fail_open=False,
        )

        alert_action = AlertInsertAction(default_status="open")

        misconfig_email.set_context(ctx)
        spoof_email.set_context(ctx)
        alert_action.set_context(ctx)

        routes = {}
        if need_mis:
            print("Misconfiguration email or alerting enabled.")
            routes[StrictAlignmentMisconfigurationPattern.name] = [misconfig_email, alert_action]
        if need_spoof:
            print("Spoofing email or alerting enabled.")
            routes[BothFailPolicyPattern.name] = [spoof_email, alert_action]

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
