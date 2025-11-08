# patterns/core.py
from __future__ import annotations
import io
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Protocol, runtime_checkable, Optional
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
    fall_through: bool = True  # whether to continue with other patterns after match

    def __init__(
        self,
        fall_through: bool = True,
    ):
        self.fall_through = fall_through

    def test(self, record_elem, policy_published_elem) -> List[Match]: ...
    async def test_async(self, record_elem, policy_published_elem) -> List[Match]: ...  # type: ignore[empty-body]


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

    def _dispatch(self, pattern: Pattern, matches: List[Match]) -> int:
        if not matches:
            return 0
        for m in matches:
            if m.xml_snippet is None:
                # xml_snippet is attached by the scan methods before dispatch
                pass
        for action in self._routes.get(pattern.name, []):
            action.run(matches)
        return len(matches)

    def _clone_elem(self, elem):
        # Detach from the tree so later .clear() doesn’t wipe it
        return ET.fromstring(ET.tostring(elem, encoding="unicode", method="xml"))

    def scan_string(self, xml_text: str) -> int:
        """
        Stream-parse XML from an in-memory string and dispatch actions on matches.
        """
        matches_count = 0
        context = ET.iterparse(io.StringIO(xml_text), events=("end",))
        policy_published_elem = None

        for _, elem in context:
            tag = elem.tag.lower()
            if tag.endswith("policy_published"):
                policy_published_elem = self._clone_elem(elem)

            if tag.endswith("record"):
                snippet = ET.tostring(elem, encoding="unicode", method="xml")
                for p in self._patterns:
                    print(f"Testing Pattern: {p.name}.")
                    found = p.test(elem, policy_published_elem)
                    for m in found:
                        if m.xml_snippet is None:
                            object.__setattr__(m, "xml_snippet", snippet)  # type: ignore
                    matches_count += self._dispatch(p, found)
                    if found and not p.fall_through:
                        break
                elem.clear()
        print(f"scan_string: Total Matches: {matches_count}")
        return matches_count

    async def scan_string_async(self, xml_text: str) -> int:
        """
        Stream-parse XML from an in-memory string and dispatch actions on matches.
        Mirrors engine.scan_string() but does this asynchronously.
        """
        matches_count = 0
        context = ET.iterparse(io.StringIO(xml_text), events=("end",))
        policy_published_elem = None

        for _, elem in context:
            tag = elem.tag.lower()
            if tag.endswith("policy_published"):
                policy_published_elem = self._clone_elem(elem)

            if tag.endswith("record"):
                snippet = ET.tostring(elem, encoding="unicode", method="xml")
                for p in self._patterns:
                    print(f"Testing Pattern: {p.name}.")
                    if hasattr(p, "test_async"):
                        found = await p.test_async(elem, policy_published_elem)  # type: ignore[attr-defined]
                    else:
                        found = p.test(elem, policy_published_elem)
                    for m in found:
                        if m.xml_snippet is None:
                            object.__setattr__(m, "xml_snippet", snippet)  # type: ignore
                    matches_count += self._dispatch(p, found)
                    if found and not p.fall_through:
                        break
                elem.clear()
        print(f"scan_string_async: Total Matches: {matches_count}")
        return matches_count
