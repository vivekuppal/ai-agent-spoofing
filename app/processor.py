# app/processor.py
from typing import Any, Dict

import json


async def process_file(content: bytes, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Implement your component logic here.
    'content' is the exact bytes of the uploaded GCS object.
    'context' gives you bucket/name/generation and the raw event payload.
    Return a JSON-serializable result.
    """
    # Example: If the file looks like JSON, parse it; else just echo stats.
    try:
        maybe_json = json.loads(content.decode("utf-8"))
        kind = "json"
        size = len(content)
        return {"kind": kind, "size": size, "keys": list(maybe_json)[:10]}
    except Exception:
        return {"kind": "bytes", "size": len(content)}
