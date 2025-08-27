# patterns/dmarc_patterns.py
from __future__ import annotations
import os
from typing import List
from dataclasses import dataclass
from app.patterns.core import Match, Pattern
from defusedxml import ElementTree as ET


@dataclass
class BothFailPolicyPattern(Pattern):
    """
    Detects: <policy_evaluated><dkim>fail</dkim> AND <spf>fail</spf>
    (case-insensitive)
    """
    name: str = "SPF_AND_DKIM_FAIL"
    severity: str = "high"

    def test(self, record_elem) -> List[Match]:
        def text_of(child_tag: str) -> str | None:
            for c in record_elem.iter():
                if c.tag.lower().endswith(child_tag):
                    return (c.text or "").strip()
            return None

        # Narrow search to the policy_evaluated node (robust to namespaces)
        policy = None
        for c in record_elem.iter():
            if c.tag.lower().endswith("policy_evaluated"):
                policy = c
                break
        if policy is None:
            return []

        def child_text(parent, tag):
            if parent is None:
                return None
            for c in parent:
                if c.tag.lower().endswith(tag):
                    return (c.text or "").strip()
            return None

        dmarc_dkim_val: str = (child_text(policy, "dkim") or "").lower()
        dmarc_spf_val = (child_text(policy, "spf") or "").lower()
        dmarc_disposition = (child_text(policy, "disposition") or "").lower()

        if dmarc_dkim_val != "fail" or dmarc_spf_val != "fail":
            return []

        # Helpful metadata for downstream actions
        src_ip = None
        header_from = None
        for c in record_elem.iter():
            t = c.tag.lower()
            if t.endswith("source_ip"):
                src_ip = (c.text or "").strip()
            elif t.endswith("header_from"):
                header_from = (c.text or "").strip()

        auth_results = None
        for c in record_elem.iter():
            t = c.tag.lower()
            if t.endswith("auth_results"):
                auth_results = c
                break

        dkim_auth = None
        spf_auth = None
        for c in auth_results.iter():
            t = c.tag.lower()
            if t.endswith("dkim"):
                dkim_auth = c
            if t.endswith("spf"):
                spf_auth = c
        dkim_auth_domain_val = (child_text(dkim_auth, "domain") or "").lower()
        dkim_auth_selector_val = (child_text(dkim_auth, "selector") or "").lower()
        dkim_auth_result_val = (child_text(dkim_auth, "result") or "").lower()

        spf_auth_domain_val = (child_text(spf_auth, "domain") or "").lower()
        spf_auth_result_val = (child_text(spf_auth, "result") or "").lower()

        return [Match(
            pattern_name=self.name,
            severity=self.severity,
            message="Both DKIM and SPF failed under policy_evaluated.",
            environment="production" if os.getenv("DESKTOP_ENV", "false").lower() not in {"1", "true", "yes"} else "development",
            metadata={
                "source_ip": src_ip,
                "header_from": header_from,
                "dmarc_result": "fail",
                "dmarc_disposition": dmarc_disposition,
                "dmarc_dkim_result": dmarc_dkim_val,
                "dmarc_spf_result": dmarc_spf_val,
                "spf_aligned": dmarc_spf_val != "fail",
                "dkim_aligned": dmarc_dkim_val != "fail",
                "auth_spf_result": spf_auth_result_val,
                "auth_spf_domain": spf_auth_domain_val,
                "auth_dkim_result": dkim_auth_result_val,
                "auth_dkim_domain": dkim_auth_domain_val,
                "auth_dkim_selector": dkim_auth_selector_val,
                "xml_snippet": ET.tostring(record_elem, encoding="unicode",
                                           method="xml")
            }
        )]
