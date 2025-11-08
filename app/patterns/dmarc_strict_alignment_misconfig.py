# patterns/dmarc_strict_alignment_misconfig.py
from __future__ import annotations
import os
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from defusedxml import ElementTree as ET
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.patterns.core import Match, Pattern
from app.xml import dmarc


logger = logging.getLogger(__name__)


def _is_subdomain(sub: str, parent: str) -> bool:
    try:
        s = sub.lower().strip(".")
        p = parent.lower().strip(".")
        return s != p and s.endswith("." + p)
    except Exception:
        return False


def _safe_int(s: Optional[str], default: int = 1) -> int:
    try:
        return int(s) if s not in (None, "") else default
    except Exception:
        return default


def _detect_policy_published(record_elem) -> Optional[ET.Element]:
    """
    Try to locate <policy_published>. Prefer climbing to the document root if available.
    Note: stdlib ElementTree doesn't expose parent/root easily; some implementations
    (like lxml) offer getroottree(). We use it if present; otherwise try relative search
    (which will usually not see siblings up at the root).
    """
    ns = dmarc.detect_default_ns_from_elem(record_elem)

    # 1) If nested under record (rare, but vendors can be quirky)
    local = dmarc.find(record_elem, "policy_published", ns)
    if local is not None:
        return local

    # 2) If the implementation provides a root accessor, use it
    getroottree = getattr(record_elem, "getroottree", None)
    if callable(getroottree):
        try:
            root = getroottree().getroot()
            return dmarc.find(root, "policy_published",
                              dmarc.detect_default_ns_from_elem(root))
        except Exception:
            pass

    return None


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
class StrictAlignmentMisconfigurationPattern(Pattern):
    """
    Detects: policy_evaluated DKIM=fail and SPF=fail for Header From domain,
    while auth_results show DKIM pass and SPF pass on subdomains of Header From.
    """

    name: str = "STRICT_ALIGNMENT_MISCONFIG_SUBDOMAIN_PASSES"

    def __init__(
        self,
        file_hash: str,
        fall_through: bool = True,
        db: Optional[AsyncSession] = None,   # injected AsyncSession
    ):
        Pattern.__init__(self, fall_through=fall_through)
        self.file_hash = file_hash
        self._db = db

    # Optional sync path (no DB) — used by the sync engine
    def test(self, record_elem, policy_published_elem) -> List[Match]:
        return []  # encourage async path for this pattern

    # Async path with DB enrichment at the last step
    async def test_async(self, record_elem, policy_published_elem) -> List[Match]:
        ns = dmarc.detect_default_ns_from_elem(record_elem)

        policy = dmarc.find(record_elem, "policy_evaluated", ns)
        if policy is None:
            return []

        dmarc_dkim_val = (dmarc.text(dmarc.find(policy, "dkim", ns)) or "").lower()
        dmarc_spf_val = (dmarc.text(dmarc.find(policy, "spf", ns)) or "").lower()
        dmarc_disposition = (dmarc.text(dmarc.find(policy, "disposition", ns)) or "").lower()
        if dmarc_dkim_val != "fail" or dmarc_spf_val != "fail":
            return []

        row = dmarc.find(record_elem, "row", ns)
        source_ip = dmarc.text(dmarc.find(row, "source_ip", ns)) if row is not None else None

        identifiers = dmarc.find(record_elem, "identifiers", ns)
        header_from = dmarc.text(dmarc.find(identifiers, "header_from", ns)) if identifiers is not None else None
        if not header_from:
            return []

        count_text = dmarc.text(dmarc.find(row, "count", ns)) if row is not None else None
        message_count = _safe_int(count_text, default=1)

        auth_results = dmarc.find(record_elem, "auth_results", ns)
        if auth_results is None:
            return []

        dkim_pass_domains: List[Dict[str, Any]] = []
        for d in dmarc.findall(auth_results, "dkim", ns):
            res = (dmarc.text(dmarc.find(d, "result", ns)) or "").lower()
            dom = (dmarc.text(dmarc.find(d, "domain", ns)) or "").lower()
            sel = (dmarc.text(dmarc.find(d, "selector", ns)) or "").lower()
            if res == "pass" and dom and _is_subdomain(dom, header_from):
                dkim_pass_domains.append({"domain": dom, "selector": sel})

        spf_pass_domains: List[Dict[str, Any]] = []
        for s in dmarc.findall(auth_results, "spf", ns):
            res = (dmarc.text(dmarc.find(s, "result", ns)) or "").lower()
            dom = (dmarc.text(dmarc.find(s, "domain", ns)) or "").lower()
            scope = (dmarc.text(dmarc.find(s, "scope", ns)) or "").lower()
            if res == "pass" and dom and _is_subdomain(dom, header_from):
                spf_pass_domains.append({"domain": dom, "scope": scope})

        if not dkim_pass_domains or not spf_pass_domains:
            return []

        adkim = aspf = None
        pp = _detect_policy_published(record_elem)
        if pp is not None:
            pp_ns = dmarc.detect_default_ns_from_elem(pp)
            adkim = (dmarc.text(dmarc.find(pp, "adkim", pp_ns)) or "").lower()
            aspf = (dmarc.text(dmarc.find(pp, "aspf", pp_ns)) or "").lower()

        strict_hints: List[str] = []
        if adkim == "s":
            strict_hints.append("adkim=s")
        if aspf == "s":
            strict_hints.append("aspf=s")

        message = (
            f"DMARC failed (DKIM+SPF) for Header From {header_from}, but DKIM and SPF "
            f"both passed for subdomain(s). Policy uses strict alignment ({', '.join(strict_hints)}); "
            "this likely indicates an alignment configuration issue."
            if strict_hints else
            "DMARC failed (DKIM+SPF) for Header From "
            f"{header_from}, while DKIM and SPF passed for subdomain(s). "
            "This likely indicates an alignment configuration issue."
        )

        environment = (
            "production"
            if os.getenv("DESKTOP_ENV", "false").lower() not in {"1", "true", "yes"}
            else "development"
        )

        computed_severity = _severity_from_policy_p(policy_published_elem)

        metadata: Dict[str, Any] = {
            "source_ip": source_ip,
            "header_from": header_from,
            "dmarc_disposition": dmarc_disposition,
            "dmarc_dkim_result": dmarc_dkim_val,
            "dmarc_spf_result": dmarc_spf_val,
            "auth_dkim_pass_subdomains": dkim_pass_domains,
            "auth_spf_pass_subdomains": spf_pass_domains,
            "message_count": message_count,
            "likely_cause": (
                "Strict alignment with auth on subdomain (misalignment)." if strict_hints
                else "Misalignment between Header From and authenticated identifiers."
            ),
            "policy_adkim": adkim,
            "policy_aspf": aspf,
            "suggested_fix": (
                "Either align DKIM/SPF to the exact Header From domain, or relax alignment "
                "by setting adkim=r and aspf=r in policy_published."
            ),
            "xml_snippet": ET.tostring(record_elem, encoding="unicode", method="xml"),
        }

        # LAST STEP: async DB lookup to enrich IDs (only if db + required params exist)
        if self._db and self.file_hash and source_ip:
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
                "disp": dmarc_disposition,
                "dkim": dmarc_dkim_val,
                "spf": dmarc_spf_val,
                "ip": source_ip,
            }
            # print(f"sql: {sql}")
            # print(f"params: {params}")

            try:
                result = await self._db.execute(sql, params)
                row = result.first()
                if row:
                    m = row._mapping
                    metadata["dmarc_report_id"] = m.get("dmarc_report_id")
                    metadata["dmarc_report_detail_id"] = m.get("id")
            except Exception as ex:
                print(f"DB lookup error in StrictAlignmentMisconfigurationPattern: {ex}")
                logger.error("DB lookup error in StrictAlignmentMisconfigurationPattern", exc_info=True)
                metadata.setdefault("lookup_error", str(ex))

        # print(metadata)

        return [Match(
            pattern_name=self.name,
            severity=computed_severity,
            message=message,
            environment=environment,
            metadata=metadata,
        )]
