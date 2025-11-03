# patterns/dmarc_patterns.py
from __future__ import annotations
import os
from typing import List, Optional
from dataclasses import dataclass
from defusedxml import ElementTree as ET
from app.patterns.core import Match, Pattern
from app.xml import dmarc  # <-- your shared XML helpers


def _safe_int(s: Optional[str], default: int = 1) -> int:
    try:
        return int(s) if s not in (None, "") else default
    except Exception:
        return default


@dataclass
class BothFailPolicyPattern(Pattern):
    """
    Detects: <policy_evaluated><dkim>fail</dkim> AND <spf>fail</spf>
    (case-insensitive)
    """
    name: str = "SPF_AND_DKIM_FAIL"
    severity: str = "high"

    def __init__(self, fall_through: bool = True):
        Pattern.__init__(self, fall_through=fall_through)

    def test(self, record_elem) -> List[Match]:
        # Detect default namespace from this subtree (works even without root)
        ns = dmarc.detect_default_ns_from_elem(record_elem)

        # policy_evaluated
        policy = dmarc.find(record_elem, "policy_evaluated", ns)
        if policy is None:
            return []

        dkim_val = (dmarc.text(dmarc.find(policy, "dkim", ns)) or "").lower()
        spf_val = (dmarc.text(dmarc.find(policy, "spf", ns)) or "").lower()
        disp_val = (dmarc.text(dmarc.find(policy, "disposition", ns)) or "").lower()

        if dkim_val != "fail" or spf_val != "fail":
            return []

        # Row / counts / identifiers
        row = dmarc.find(record_elem, "row", ns)
        count_text = dmarc.text(dmarc.find(row, "count", ns))
        message_count = _safe_int(count_text, default=1)

        source_ip = dmarc.text(dmarc.find(row, "source_ip", ns))

        identifiers = dmarc.find(record_elem, "identifiers", ns)
        header_from = dmarc.text(dmarc.find(identifiers, "header_from", ns))

        # auth_results (first DKIM/SPF blocks if present)
        auth_results = dmarc.find(record_elem, "auth_results", ns)

        dkim_auth = dmarc.find(auth_results, "dkim", ns) if auth_results is not None else None
        spf_auth = dmarc.find(auth_results, "spf", ns)  if auth_results is not None else None

        dkim_auth_domain = (dmarc.text(dmarc.find(dkim_auth, "domain", ns)) or "").lower() if dkim_auth is not None else ""
        dkim_auth_selector = (dmarc.text(dmarc.find(dkim_auth, "selector", ns)) or "").lower() if dkim_auth is not None else ""
        dkim_auth_result = (dmarc.text(dmarc.find(dkim_auth, "result", ns)) or "").lower() if dkim_auth is not None else ""

        spf_auth_domain = (dmarc.text(dmarc.find(spf_auth, "domain", ns)) or "").lower() if spf_auth is not None else ""
        spf_auth_result = (dmarc.text(dmarc.find(spf_auth, "result", ns)) or "").lower() if spf_auth is not None else ""

        return [Match(
            pattern_name=self.name,
            severity=self.severity,
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
            },
        )]

