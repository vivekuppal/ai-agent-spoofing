# patterns/dmarc_patterns.py
from __future__ import annotations
import os
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from defusedxml import ElementTree as ET
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.patterns.core import Match, Pattern
from app.xml import dmarc


def _safe_int(s: Optional[str], default: int = 1) -> int:
    try:
        return int(s) if s not in (None, "") else default
    except Exception:
        return default


def _severity_from_policy_p(pp_elem) -> str:
    try:
        ns = dmarc.detect_default_ns_from_elem(pp_elem) if pp_elem is not None else {}
        p_val = (dmarc.text(dmarc.find(pp_elem, "p", ns)) or "").lower() if pp_elem is not None else ""
    except Exception:
        p_val = ""
    if p_val == "none":
        return "high"
    if p_val == "quarantine":
        return "medium"
    if p_val == "reject":
        return "low"
    return "medium"


@dataclass
class BothFailPolicyPattern(Pattern):
    name: str = "SPF_AND_DKIM_FAIL"
    severity: str = "high"  # default; will be overridden per-policy

    def __init__(
            self,
            file_hash: str,
            fall_through: bool = True,
            db: Optional[AsyncSession] = None
    ):
        Pattern.__init__(self, fall_through=fall_through)
        self.file_hash = file_hash
        self._db = db

    # sync path (no DB)
    def test(self, record_elem, policy_published_elem) -> List[Match]:
        ns = dmarc.detect_default_ns_from_elem(record_elem)
        policy = dmarc.find(record_elem, "policy_evaluated", ns)
        if policy is None:
            return []

        dkim_val = (dmarc.text(dmarc.find(policy, "dkim", ns)) or "").lower()
        spf_val = (dmarc.text(dmarc.find(policy, "spf", ns)) or "").lower()
        disp_val = (dmarc.text(dmarc.find(policy, "disposition", ns)) or "").lower()
        if dkim_val != "fail" or spf_val != "fail":
            return []

        row = dmarc.find(record_elem, "row", ns)
        count_text = dmarc.text(dmarc.find(row, "count", ns))
        message_count = _safe_int(count_text, default=1)
        source_ip = dmarc.text(dmarc.find(row, "source_ip", ns))
        identifiers = dmarc.find(record_elem, "identifiers", ns)
        header_from = dmarc.text(dmarc.find(identifiers, "header_from", ns))

        auth_results = dmarc.find(record_elem, "auth_results", ns)
        dkim_auth = dmarc.find(auth_results, "dkim", ns) if auth_results is not None else None
        spf_auth = dmarc.find(auth_results, "spf",  ns) if auth_results is not None else None

        dkim_auth_domain = (dmarc.text(dmarc.find(dkim_auth, "domain", ns)) or "").lower() if dkim_auth is not None else ""
        dkim_auth_selector = (dmarc.text(dmarc.find(dkim_auth, "selector", ns)) or "").lower() if dkim_auth is not None else ""
        dkim_auth_result = (dmarc.text(dmarc.find(dkim_auth, "result", ns)) or "").lower() if dkim_auth is not None else ""
        spf_auth_domain = (dmarc.text(dmarc.find(spf_auth,  "domain", ns)) or "").lower() if spf_auth  is not None else ""
        spf_auth_result = (dmarc.text(dmarc.find(spf_auth,  "result", ns)) or "").lower() if spf_auth  is not None else ""

        computed_severity = _severity_from_policy_p(policy_published_elem)

        return [Match(
            pattern_name=self.name,
            severity=computed_severity,     # <-- severity from <policy_published><p>
            message="Both DKIM and SPF failed under policy_evaluated.",
            environment="production" if os.getenv("DESKTOP_ENV", "false").lower() not in {"1", "true", "yes"} else "development",
            metadata={
                "source_ip": source_ip,
                "header_from": header_from,
                "dmarc_result": "fail",
                "dmarc_disposition": disp_val,
                "dmarc_dkim_result": dkim_val,
                "dmarc_spf_result": spf_val,
                "spf_aligned": spf_val != "fail",
                "dkim_aligned": dkim_val != "fail",
                "auth_spf_result": spf_auth_result,
                "auth_spf_domain": spf_auth_domain,
                "message_count": message_count,
                "auth_dkim_result": dkim_auth_result,
                "auth_dkim_domain": dkim_auth_domain,
                "auth_dkim_selector": dkim_auth_selector,
                "xml_snippet": ET.tostring(record_elem, encoding="unicode", method="xml"),
                "alert_priority": "high",
                # optional: keep a snapshot of policy p for downstream analytics
                "policy_p": (dmarc.text(dmarc.find(policy_published_elem, "p", dmarc.detect_default_ns_from_elem(policy_published_elem))) if policy_published_elem is not None else None),
            },
        )]

    async def test_async(self, record_elem, policy_published_elem) -> List[Match]:
        matches = self.test(record_elem, policy_published_elem)
        if not matches or not self._db or not self.file_hash:
            return matches

        md = matches[0].metadata
        source_ip = md.get("source_ip")
        disp = md.get("dmarc_disposition")
        dkim_val = md.get("dmarc_dkim_result")
        spf_val = md.get("dmarc_spf_result")
        if not (source_ip and disp and dkim_val is not None and spf_val is not None):
            return matches

        sql = text("""
            SELECT pf.dmarc_report_id, drd.id
            FROM processed_file pf
            INNER JOIN dmarc_report_details drd
                ON drd.dmarc_report_id = pf.dmarc_report_id
            WHERE pf.file_hash = :file_hash
              AND pf.status = 'done'
              AND drd.disposition = :disp
              AND drd.dkim = :dkim
              AND drd.spf = :spf
              AND drd.source_ip = :ip
            LIMIT 1
        """)
        params = {
            "file_hash": self.file_hash,
            "disp": disp,
            "dkim": dkim_val,
            "spf": spf_val,
            "ip": source_ip,
        }
        try:
            result = await self._db.execute(sql, params)
            row = result.first()
            if row:
                m = row._mapping
                md["dmarc_report_id"] = m.get("dmarc_report_id")
                md["dmarc_report_detail_id"] = m.get("id")
        except Exception as ex:
            md.setdefault("lookup_error", str(ex))

        return matches
