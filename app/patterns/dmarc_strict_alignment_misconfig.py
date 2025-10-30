# patterns/dmarc_strict_alignment_misconfig.py
from __future__ import annotations
import os
from typing import List, Optional
from dataclasses import dataclass
from defusedxml import ElementTree as ET
from app.patterns.core import Match, Pattern


def _text_of_first_child(parent, tag_endswith: str) -> Optional[str]:
    if parent is None:
        return None
    for c in parent:
        if c.tag.lower().endswith(tag_endswith):
            return (c.text or "").strip()
    return None


def _iter_children_with_suffix(parent, tag_endswith: str):
    if parent is None:
        return
    for c in parent:
        if c.tag.lower().endswith(tag_endswith):
            yield c


def _find_first(elem, tag_endswith: str):
    for c in elem.iter():
        if c.tag.lower().endswith(tag_endswith):
            return c
    return None


def _find_policy_published_anywhere(record_elem) -> Optional[ET.Element]:
    node = _find_first(record_elem, "policy_published")
    if node is not None:
        return node

    getroottree = getattr(record_elem, "getroottree", None)
    if callable(getroottree):
        try:
            root = getroottree().getroot()
            for c in root.iter():
                if c.tag.lower().endswith("policy_published"):
                    return c
        except Exception:
            pass
    return None


def _is_subdomain(sub: str, parent: str) -> bool:
    try:
        s = sub.lower().strip(".")
        p = parent.lower().strip(".")
        return s != p and s.endswith("." + p)
    except Exception:
        return False


def _safe_int(s: Optional[str], default: int = 1) -> int:
    try:
        return int(s) if s is not None else default
    except Exception:
        return default


@dataclass
class StrictAlignmentMisconfigurationPattern(Pattern):
    """
    Detects: policy_evaluated DKIM=fail and SPF=fail for Header From domain,
    while auth_results show DKIM pass and SPF pass on subdomains of Header From.
    """
    name: str = "STRICT_ALIGNMENT_MISCONFIG_SUBDOMAIN_PASSES"
    severity: str = "medium"

    def __init__(self, fall_through: bool = True):
        Pattern.__init__(self, fall_through=fall_through)

    def test(self, record_elem) -> List[Match]:
        # --- DMARC policy_evaluated must be fail/fail ---
        policy = _find_first(record_elem, "policy_evaluated")
        if policy is None:
            return []

        dmarc_dkim_val = (_text_of_first_child(policy, "dkim") or "").lower()
        dmarc_spf_val = (_text_of_first_child(policy, "spf") or "").lower()
        dmarc_disposition = (_text_of_first_child(policy, "disposition") or "").lower()

        if dmarc_dkim_val != "fail" or dmarc_spf_val != "fail":
            return []

        # --- header_from & source_ip (context) ---
        header_from = None
        source_ip = None
        for c in record_elem.iter():
            t = c.tag.lower()
            if t.endswith("header_from"):
                header_from = (c.text or "").strip()
            elif t.endswith("source_ip"):
                source_ip = (c.text or "").strip()
        if not header_from:
            return []

        # --- extract <row><count> for message_count ---
        row_node = _find_first(record_elem, "row")
        count_text = _text_of_first_child(row_node, "count")
        message_count = _safe_int(count_text, default=1)

        # --- auth_results: require at least one DKIM pass and one SPF pass on subdomains of header_from ---
        auth_results = _find_first(record_elem, "auth_results")
        if auth_results is None:
            print("StrictAlignmentMisconfigurationPattern: No auth_results found")
            return []

        dkim_pass_domains = []
        for dkim_node in _iter_children_with_suffix(auth_results, "dkim"):
            res = (_text_of_first_child(dkim_node, "result") or "").lower()
            dom = (_text_of_first_child(dkim_node, "domain") or "").lower()
            sel = (_text_of_first_child(dkim_node, "selector") or "").lower()
            if res == "pass" and dom and _is_subdomain(dom, header_from):
                dkim_pass_domains.append({"domain": dom, "selector": sel})

        spf_pass_domains = []
        for spf_node in _iter_children_with_suffix(auth_results, "spf"):
            res = (_text_of_first_child(spf_node, "result") or "").lower()
            dom = (_text_of_first_child(spf_node, "domain") or "").lower()
            scope = (_text_of_first_child(spf_node, "scope") or "").lower()
            if res == "pass" and dom and _is_subdomain(dom, header_from):
                spf_pass_domains.append({"domain": dom, "scope": scope})

        if not dkim_pass_domains or not spf_pass_domains:
            print("StrictAlignmentMisconfigurationPattern: No DKIM/SPF pass on subdomains found")
            return []

        # --- Build match ---
        message = (
            f"DMARC failed (DKIM+SPF) for the Header From domain {header_from}, but DKIM and SPF "
            "both passed for subdomain(s). Policy shows strict alignment (adkim=s, aspf=s), "
            "so this is likely a configuration/ alignment issue."
        )

        environment = (
            "production"
            if os.getenv("DESKTOP_ENV", "false").lower() not in {"1", "true", "yes"}
            else "development"
        )

        print("dmarc_spf_val:", dmarc_spf_val)
        print("dmarc_dkim_val:", dmarc_dkim_val)

        return [
            Match(
                pattern_name=self.name,
                severity=self.severity,
                message=message,
                environment=environment,
                metadata={
                    "source_ip": source_ip,
                    "header_from": header_from,
                    "dmarc_disposition": dmarc_disposition,
                    "dmarc_dkim_result": dmarc_dkim_val,
                    "dmarc_spf_result": dmarc_spf_val,
                    "auth_dkim_pass_subdomains": dkim_pass_domains,
                    "auth_spf_pass_subdomains": spf_pass_domains,
                    "message_count": message_count,
                    "likely_cause": "Strict alignment with auth on subdomain (misalignment).",
                    "suggested_fix": (
                        "Either align auth to the exact Header From domain, or relax alignment "
                        "by setting adkim=r and aspf=r in policy_published."
                    ),
                    "xml_snippet": ET.tostring(record_elem, encoding="unicode", method="xml"),
                },
            )
        ]
