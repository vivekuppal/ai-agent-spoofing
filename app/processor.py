# app/processor.py
from __future__ import annotations
from typing import Any, Dict
from app.patterns.core import XmlPatternEngine
from app.patterns.dmarc_patterns import BothFailPolicyPattern
from app.action.email_action import EmailAction
from app.emailsender import EmailSender


async def process_file(content: bytes, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Implement component logic here.
    'content' is the exact bytes of the uploaded GCS object.
    'context' gives bucket/name/generation and the raw event payload.
    Return a JSON-serializable result.
    """
    # Example: we expect the content to be a DMARC XML file.
    # If the content is not valid XML, it will raise an exception.
    try:
        # Create an XML pattern engine with the registered patterns
        patterns = [BothFailPolicyPattern()]
        routes = {
            BothFailPolicyPattern.name: [
                EmailAction(
                    sender=context["email_sender"],
                    from_addr="webapp@lappuai.com",
                    to_addrs=["vivek.uppal@gmail.com", "vivek@lappuai.com"],
                    subject_prefix="[Spoofing Alert]"
                )
            ]
        }
        engine = XmlPatternEngine(patterns, routes)
        # Process the XML content
        matches_count = engine.scan_string(content.decode("utf-8"))
        return {"matches_count": matches_count}
    except Exception as ex:
        print(f"Error processing file: {ex}")
        return {"kind": "bytes", "size": len(content)}


def example_in_memory_xml_with_email():
    """
    Demonstrates pattern detection from an in-memory DMARC XML string.
    If BothFailPolicyPattern matches, an email is sent via EmailSender.
    """
    # In-memory XML with two records: one matches (both fail), one does not.
    xml_text = """<?xml version="1.0" encoding="UTF-8"?>
    <feedback>
      <record>
        <row>
          <source_ip>23.83.217.29</source_ip>
          <count>1</count>
          <policy_evaluated>
            <disposition>none</disposition>
            <dkim>fail</dkim>
            <spf>fail</spf>
          </policy_evaluated>
        </row>
        <identifiers>
          <header_from>nextorbit.co</header_from>
        </identifiers>
        <auth_results>
          <spf>
            <domain>srv1167.main-hosting.eu</domain>
            <result>pass</result>
          </spf>
        </auth_results>
      </record>

      <record>
        <row>
          <source_ip>203.0.113.8</source_ip>
          <count>2</count>
          <policy_evaluated>
            <disposition>none</disposition>
            <dkim>pass</dkim>
            <spf>fail</spf>
          </policy_evaluated>
        </row>
        <identifiers>
          <header_from>example.com</header_from>
        </identifiers>
      </record>
    </feedback>
    """

    # --- configure EmailSender (fill in your real SMTP settings) ---
    smtp_host = "smtp.dreamhost.com"       # or your provider
    smtp_port = 587
    username  = "alerts@yourdomain.com"
    password  = "APP_PASSWORD"
    to_list   = ["you@yourdomain.com"]     # one or more recipients

    # We keep a persistent connection for the demo run
    with EmailSender(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        username=username,
        password=password,
        use_tls=(smtp_port == 587),
        use_ssl=(smtp_port == 465),
    ) as sender:

        # Register pattern(s)
        patterns = [BothFailPolicyPattern()]

        # Route pattern -> actions (here: send a single summarized email per matched record)
        routes = {
            "both_fail_policy": [
                EmailAction(
                    sender=sender,
                    from_addr=username,
                    to_addrs=to_list,
                    subject_prefix="[Spoofing Alert]",
                    use_html=True,
                )
            ]
        }

        engine = XmlPatternEngine(patterns, routes)

        # Run the scan on the in-memory XML string
        hits = engine.scan_string(xml_text)
        print(f"demo_in_memory_xml_with_email: dispatched {hits} match(es).")


if __name__ == "__main__":
    example_in_memory_xml_with_email()
