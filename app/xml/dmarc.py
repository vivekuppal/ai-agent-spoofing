# app/xml/dmarc.py
from __future__ import annotations
from typing import Dict, Iterable, Optional, List
from defusedxml import ElementTree as ET  # use defusedxml everywhere for safety


def detect_default_ns_from_elem(elem: ET.Element) -> Dict[str, str]:
    """If the element uses a default ns, return a prefix mapping; else {}."""
    tag = (elem.tag or "")
    if tag.startswith("{"):
        uri = tag[1:].split("}", 1)[0]
        return {"d": uri}
    return {}


def parse(xml_bytes: bytes) -> ET.Element:
    """Parse bytes and return root element (defused)."""
    return ET.fromstring(xml_bytes)


def detect_default_ns(root: ET.Element) -> Dict[str, str]:
    """
    If the document uses a default ns (e.g., <feedback xmlns="...">),
    return a prefix mapping like {"d": "<ns-uri>"}; else {}.
    """
    tag = (root.tag or "")
    if tag.startswith("{"):
        uri = tag[1:].split("}", 1)[0]
        return {"d": uri}
    return {}


def _try_paths(elem: Optional[ET.Element], paths: Iterable[str], ns: Optional[Dict[str, str]]) -> Optional[ET.Element]:
    if elem is None:
        return None
    for p in paths:
        try:
            # Pass ns only if prefix is used; otherwise plain find
            if p.find("d:") != -1 and ns:
                hit = elem.find(p, ns)
            else:
                hit = elem.find(p)
        except SyntaxError:
            # e.g., "prefix 'd' not found" -> skip to next path
            continue
        if hit is not None:
            return hit
    return None


def _try_paths_all(elem: Optional[ET.Element], paths: Iterable[str], ns: Optional[Dict[str, str]]) -> List[ET.Element]:
    if elem is None:
        return []
    for p in paths:
        try:
            if p.find("d:") != -1 and ns:
                hits = elem.findall(p, ns)
            else:
                hits = elem.findall(p)
        except SyntaxError:
            continue
        if hits:
            return hits
    return []


def q(local: str, ns: Optional[Dict[str, str]]) -> List[str]:
    """
    Build candidate XPath fragments for one local name.
    Only include the prefixed form if a prefix map is present.
    """
    paths: List[str] = []
    if ns and "d" in ns:
        paths.append(f".//d:{local}")
    paths.append(f".//{local}")
    return paths


def find(elem: Optional[ET.Element], local: str, ns: Optional[Dict[str, str]]) -> Optional[ET.Element]:
    return _try_paths(elem, q(local, ns), ns)


def findall(elem: Optional[ET.Element], local: str, ns: Optional[Dict[str, str]]) -> List[ET.Element]:
    return _try_paths_all(elem, q(local, ns), ns)


def text(elem: Optional[ET.Element]) -> Optional[str]:
    return (elem.text or "").strip() if elem is not None and elem.text is not None else None


def localname(tag: str) -> str:
    """Return the local part of a tag, stripping '{ns}' if present."""
    return tag.split('}', 1)[-1]
