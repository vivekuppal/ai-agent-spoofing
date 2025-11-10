# actions/alert_action.py
from __future__ import annotations
from typing import Callable, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.patterns.core import Match, Action
from app.models import Alert
from app.feature_utils import is_subfeature_enabled_for_customer


PATTERN_TO_SUBFEATURE = {
    "SPF_AND_DKIM_FAIL": "SPOOFING_ALERT",                          # spoofing
    "STRICT_ALIGNMENT_MISCONFIG_SUBDOMAIN_PASSES": "MISCONFIGURATION_ALERT",  # misconfig
}


def _priority_from_severity(severity: Optional[str]) -> str:
    s = (severity or "").lower()
    if s in {"critical", "high"}:
        return "high"
    if s in {"medium", "moderate"}:
        return "medium"
    return "low"


class AlertInsertAction(Action):
    """Insert alerts into the database based on matches."""
    name: str = "alert_insert_action"

    def __init__(self, default_status: str = "open",
                 priority_mapper: Optional[Callable[[Optional[str]], str]] = None):
        self._default_status = default_status
        self._priority_mapper = priority_mapper or _priority_from_severity
        self._buffer: List[Match] = []

    def run(self, matches: List[Match]) -> None:
        if matches:
            self._buffer.extend(matches)

    async def _resolve_ids(self, session: AsyncSession, lp: Dict[str, Optional[str]]) -> Tuple[Optional[int], Optional[int]]:
        sql = text("""
            SELECT pf.dmarc_report_id, drd.id
            FROM processed_file pf
            JOIN dmarc_report_details drd ON drd.dmarc_report_id = pf.dmarc_report_id
            WHERE pf.file_hash = :file_hash AND pf.status = 'done'
              AND drd.disposition = :disp AND drd.dkim = :dkim
              AND drd.spf = :spf AND drd.source_ip = :ip
            LIMIT 1
        """)
        result = await session.execute(sql, {
            "file_hash": lp.get("file_hash"),
            "disp": lp.get("disp"),
            "dkim": lp.get("dkim"),
            "spf": lp.get("spf"),
            "ip": lp.get("ip"),
        })
        row = result.first()
        if not row:
            return (None, None)
        m = row._mapping
        return (m.get("dmarc_report_id"), m.get("id"))

    async def flush(self, session: AsyncSession) -> int:
        if not self._buffer:
            return 0

        to_insert: List[Alert] = []
        for m in self._buffer:
            md = m.metadata or {}
            rid = md.get("dmarc_report_id")
            rdid = md.get("dmarc_report_detail_id")
            customer_id = md.get("customer_id")

            # Feature-gate: if we know the customer, check the subfeature
            subkey = PATTERN_TO_SUBFEATURE.get(m.pattern_name)
            if subkey and customer_id is not None:
                enabled = await is_subfeature_enabled_for_customer(
                    session,
                    customer_id=customer_id,
                    feature_key=subkey,
                    respect_is_active=True,
                )
                if not enabled:
                    continue  # skip this alert

            to_insert.append(Alert(
                type=m.pattern_name,
                severity=(m.severity or "low").lower(),
                priority=(md.get("alert_priority") or self._priority_mapper(m.severity)),
                status=self._default_status,
                dmarc_report_id=rid,
                dmarc_report_detail_id=rdid,
            ))

        if not to_insert:
            self._buffer.clear()
            return 0

        if session.in_transaction():
            session.add_all(to_insert)
            await session.flush()
            await session.commit()
        else:
            async with session.begin():
                session.add_all(to_insert)

        inserted = len(to_insert)
        self._buffer.clear()
        return inserted

    async def flush1(self, session: AsyncSession) -> int:
        if not self._buffer:
            return 0

        to_insert: List[Alert] = []
        for m in self._buffer:
            md = m.metadata or {}
            rid = md.get("dmarc_report_id")
            rdid = md.get("dmarc_report_detail_id")

            to_insert.append(Alert(
                type=m.pattern_name,
                severity=(m.severity or "low").lower(),
                priority=(md.get("alert_priority")
                          or self._priority_mapper(m.severity)),
                status=self._default_status,
                dmarc_report_id=rid,
                dmarc_report_detail_id=rdid,
            ))

        if session.in_transaction():
            # Reuse the existing txn created by earlier SELECTs
            session.add_all(to_insert)
            await session.flush()    # ensure INSERTs are sent
            await session.commit()   # ✅ commit the reused txn
        else:
            # Start/commit a short transaction for the inserts
            async with session.begin():
                session.add_all(to_insert)

        inserted = len(to_insert)
        self._buffer.clear()
        return inserted
