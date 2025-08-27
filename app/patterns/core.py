# patterns/core.py
from __future__ import annotations
import io
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Protocol, runtime_checkable, Optional
from pathlib import Path
from defusedxml import ElementTree as ET
# --------- Core domain objects ---------


@dataclass(frozen=True)
class Match:
    """A single pattern match with useful context for actions."""
    pattern_name: str
    severity: str               # e.g., 'info' | 'warn' | 'critical'
    message: str
    metadata: Dict[str, Any]    # e.g., {"source_ip": "...", "header_from": "..."}
    xml_snippet: Optional[str] = None  # optional raw XML string for reference
    environment: str = "production"


@runtime_checkable
class Pattern(Protocol):
    """Pattern checks a single <record> element and returns 0..n matches."""
    name: str
    severity: str
    def test(self, record_elem) -> List[Match]: ...


@runtime_checkable
class Action(Protocol):
    """Action processes 0..n matches (batch-friendly)."""
    name: str
    def run(self, matches: List[Match]) -> None: ...

# --------- Engine ---------


class XmlPatternEngine:
    """
    Stream-parse XML, apply registered patterns to each <record>,
    and dispatch to actions.
    Uses iterparse so files can be very large.
    """
    def __init__(self, patterns: Iterable[Pattern],
                 routes: Dict[str, List[Action]]):
        """
        routes: {pattern_name: [Action, ...]}
        """
        self._patterns = list(patterns)
        self._routes = routes

    def scan_file(self, path: Path) -> int:
        """
        Stream-parse XML from a file and dispatch actions on matches.
        """
        from defusedxml import ElementTree as ET  # safe XML parser

        matches_count = 0
        # iterparse for memory efficiency; free elements after use
        context = ET.iterparse(str(path), events=("end",))
        for event, elem in context:
            # DMARC aggregate: <record> appears under <feedback>-><record>
            # but we don't assume exact root
            if elem.tag.lower().endswith("record"):
                # (Optional) capture snippet: serialize minimal element to string
                snippet = ET.tostring(elem, encoding="unicode", method="xml")

                for p in self._patterns:
                    found = p.test(elem)
                    if not found:
                        continue
                    # attach snippet to each match (optional)
                    for m in found:
                        if m.xml_snippet is None:
                            m.metadata.setdefault("file", str(path))
                            object.__setattr__(m, "xml_snippet", snippet)  # type: ignore[attr-defined]

                    # dispatch to the routed actions
                    for action in self._routes.get(p.name, []):
                        action.run(found)
                    matches_count += len(found)

                # important: clear to release memory
                elem.clear()

        return matches_count

    def scan_string(self, xml_text: str) -> int:
        """
        Stream-parse XML from an in-memory string and dispatch actions on matches.
        Mirrors engine.scan_file() but reads from a StringIO source.
        """
        print("Scanning in-memory XML string")
        matches_count = 0
        context = ET.iterparse(io.StringIO(xml_text), events=("end",))
        for event, elem in context:
            if elem.tag.lower().endswith("record"):
                # print(f"Found <record> element: {elem.tag}")
                snippet = ET.tostring(elem, encoding="unicode", method="xml")

                for p in self._patterns:  # using the same registered patterns
                    print(f"Testing pattern: {p.name}")
                    found = p.test(elem)
                    if not found:
                        continue

                    # attach helpful context
                    for m in found:
                        m.metadata.setdefault("file", "<memory>")
                        if m.xml_snippet is None:
                            # NOTE: Match is @dataclass(frozen=True); setattr like below works in our earlier code
                            object.__setattr__(m, "xml_snippet", snippet)

                    # route to actions bound to this pattern
                    for action in self._routes.get(p.name, []):
                        print(f"Running action: {action.name} for pattern: {p.name}")
                        action.run(found)

                    matches_count += len(found)

                elem.clear()  # free memory
        print(f"scan_string - Total matches found: {matches_count}")
        return matches_count
