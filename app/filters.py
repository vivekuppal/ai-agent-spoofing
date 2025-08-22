# filters.py
from html import unescape
from xml.dom import minidom


def pretty_xml(xml_text: str) -> str:
    # If it looks HTML-escaped (e.g., &lt;record&gt;), unescape before formatting
    if "&lt;" in xml_text and "<" not in xml_text:
        xml_text = unescape(xml_text)

    # Try lxml (best), fall back to minidom
    try:
        from lxml import etree  # type: ignore
        parser = etree.XMLParser(remove_blank_text=True)
        root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
        return etree.tostring(root, pretty_print=True, encoding="unicode")
    except Exception:
        # minidom fallback
        try:
            reparsed = minidom.parseString(xml_text.encode("utf-8"))
            pretty = reparsed.toprettyxml(indent="  ", encoding="unicode")
            # Strip XML declaration and empty lines
            lines = [ln for ln in pretty.splitlines() if ln.strip() and not ln.startswith("<?xml")]
            return "\n".join(lines)
        except Exception:
            # As a last resort, just return the input
            return xml_text
