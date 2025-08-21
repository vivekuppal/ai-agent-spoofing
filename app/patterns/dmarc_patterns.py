# patterns/dmarc_patterns.py
from __future__ import annotations
from typing import List
from dataclasses import dataclass
from app.patterns.core import Match, Pattern


@dataclass
class BothFailPolicyPattern(Pattern):
    """
    Detects: <policy_evaluated><dkim>fail</dkim> AND <spf>fail</spf>
    (case-insensitive)
    """
    name: str = "both_fail_policy"
    severity: str = "critical"

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
            for c in parent:
                if c.tag.lower().endswith(tag):
                    return (c.text or "").strip()
            return None

        dkim_val = (child_text(policy, "dkim") or "").lower()
        spf_val  = (child_text(policy, "spf") or "").lower()
        if dkim_val != "fail" or spf_val != "fail":
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

        return [Match(
            pattern_name=self.name,
            severity=self.severity,
            message="Both DKIM and SPF failed under policy_evaluated.",
            metadata={
                "source_ip": src_ip,
                "header_from": header_from,
                "dkim": dkim_val,
                "spf": spf_val,
            }
        )]
