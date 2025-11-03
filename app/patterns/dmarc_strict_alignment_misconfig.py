# patterns/dmarc_strict_alignment_misconfig.py
from __future__ import annotations
import os
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from defusedxml import ElementTree as ET
from app.patterns.core import Match, Pattern
from app.xml import dmarc  # <-- your shared namespace-safe helpers

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
        # print(f"Find namespace from record_elem")
        ns = dmarc.detect_default_ns_from_elem(record_elem)
        # print(f"Namespace mapping: {ns}")

        # --- DMARC policy_evaluated must be fail/fail ---
        # print(f"Find policy evaluated")
        policy = dmarc.find(record_elem, "policy_evaluated", ns)
        # print(f"Policy is: {policy}")
        if policy is None:
            return []

        # print(f"Find dkim, spf, disposition")
        dmarc_dkim_val = (dmarc.text(dmarc.find(policy, "dkim", ns)) or "").lower()
        dmarc_spf_val = (dmarc.text(dmarc.find(policy, "spf", ns)) or "").lower()
        dmarc_disposition = (dmarc.text(dmarc.find(policy, "disposition", ns)) or "").lower()

        if dmarc_dkim_val != "fail" or dmarc_spf_val != "fail":
            return []

        # --- header_from & source_ip (context) ---
        row = dmarc.find(record_elem, "row", ns)
        source_ip = dmarc.text(dmarc.find(row, "source_ip", ns))

        identifiers = dmarc.find(record_elem, "identifiers", ns)
        header_from = dmarc.text(dmarc.find(identifiers, "header_from", ns))
        if not header_from:
            return []

        # --- extract <row><count> for message_count ---
        count_text = dmarc.text(dmarc.find(row, "count", ns))
        message_count = _safe_int(count_text, default=1)

        # --- auth_results: require at least one DKIM pass and one SPF pass on subdomains of header_from ---
        auth_results = dmarc.find(record_elem, "auth_results", ns)
        if auth_results is None:
            logger.debug("StrictAlignmentMisconfigurationPattern: No <auth_results> found")
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
            logger.debug("StrictAlignmentMisconfigurationPattern: No DKIM/SPF pass on subdomains found")
            return []

        # --- (Optional) Check policy_published to confirm strict alignment flags if we can reach it ---
        adkim = aspf = None
        pp = _detect_policy_published(record_elem)
        if pp is not None:
            pp_ns = dmarc.detect_default_ns_from_elem(pp)
            adkim = (dmarc.text(dmarc.find(pp, "adkim", pp_ns)) or "").lower()
            aspf = (dmarc.text(dmarc.find(pp, "aspf", pp_ns)) or "").lower()

        strict_hints = []
        if adkim == "s":
            strict_hints.append("adkim=s")
        if aspf == "s":
            strict_hints.append("aspf=s")

        if strict_hints:
            message = (
                f"DMARC failed (DKIM+SPF) for Header From {header_from}, but DKIM and SPF "
                f"both passed for subdomain(s). Policy uses strict alignment ({', '.join(strict_hints)}); "
                "this likely indicates an alignment configuration issue."
            )
        else:
            # If we cannot confirm strict via policy_published (or it's relaxed),
            # keep the signal but phrase it carefully (as in your original).
            message = (
                f"DMARC failed (DKIM+SPF) for Header From {header_from}, while DKIM and SPF "
                "passed for subdomain(s). This is likely an alignment configuration issue "
                "(strict alignment may be in effect, or aligned identifiers differ)."
            )

        environment = (
            "production"
            if os.getenv("DESKTOP_ENV", "false").lower() not in {"1", "true", "yes"}
            else "development"
        )

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
                    "likely_cause": (
                        "Strict alignment with auth on subdomain (misalignment)."
                        if strict_hints else
                        "Misalignment between Header From and authenticated identifiers."
                    ),
                    "policy_adkim": adkim,
                    "policy_aspf": aspf,
                    "suggested_fix": (
                        "Either align DKIM/SPF to the exact Header From domain, or relax alignment "
                        "by setting adkim=r and aspf=r in policy_published."
                    ),
                    "xml_snippet": ET.tostring(record_elem, encoding="unicode", method="xml"),
                },
            )
        ]
