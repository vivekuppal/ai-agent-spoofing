# app/main.py
import base64
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException, Response
from google.cloud import storage

from .processor import process_file  # <-- your logic
from .utils import verify_pubsub_jwt_if_required, json_dumps

logger = logging.getLogger("uvicorn")
logger.setLevel(logging.INFO)

# TO DO: determine if we are copying the input file in the output
# or if we are just processing the input file and writing the output.


# Config via env
COMPONENT_NAME = os.getenv("COMPONENT_NAME", "ai-component")
EXPECTED_EVENT_TYPE = os.getenv("EXPECTED_EVENT_TYPE", "OBJECT_FINALIZE")
OBJECT_PREFIX = os.getenv("OBJECT_PREFIX", "")  # e.g. "reports/"
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", f"outputs/{COMPONENT_NAME}/")
READ_CHUNK_SIZE = int(os.getenv("READ_CHUNK_SIZE", "0"))  # 0 -> entire file


app = FastAPI(title=COMPONENT_NAME)

# Lazily created GCS client
_storage_client: Optional[storage.Client] = None


def get_storage() -> storage.Client:
    """ Returns a GCS client, creating it if not already done.
    """
    global _storage_client
    if _storage_client is None:
        _storage_client = storage.Client()
    return _storage_client


def _extract_event(body: Dict[str, Any]) -> Tuple[str, str, Optional[int], Dict[str, Any]]:
    """
    Supports the default 'wrapped' Pub/Sub push body and GCS notification payload.
    Returns: (bucket, object_id, generation, raw_payload)
    """
    # Default wrapped format: { "message": {"data": "...base64...", "attributes": {...}}, "subscription": "..." }
    msg = body.get("message") or {}
    attrs = msg.get("attributes") or {}

    bucket = attrs.get("bucketId")
    object_id = attrs.get("objectId")
    generation_raw = attrs.get("objectGeneration")
    event_type = attrs.get("eventType")
    payload_format = attrs.get("payloadFormat")

    # If not present in attributes, try data payload (GCS JSON API object)
    data_b64 = msg.get("data")
    payload = {}
    if data_b64:
        try:
            decoded = base64.b64decode(data_b64)
            payload = json.loads(decoded.decode("utf-8")) if decoded else {}
        except Exception:
            logger.warning("Failed to base64-decode/parse message.data; continuing with attributes only")

    if not bucket:
        bucket = payload.get("bucket")
    if not object_id:
        object_id = payload.get("name")
    generation = None
    if generation_raw:
        try:
            generation = int(generation_raw)
        except Exception:
            pass
    if generation is None:
        # GCS JSON API payload carries generation as string
        gen_str = payload.get("generation")
        if gen_str is not None:
            try:
                generation = int(gen_str)
            except Exception:
                pass

    # Basic gating
    if EXPECTED_EVENT_TYPE and event_type and event_type != EXPECTED_EVENT_TYPE:
        raise HTTPException(status_code=204, detail=f"Ignored eventType={event_type}")

    if OBJECT_PREFIX and object_id and not object_id.startswith(OBJECT_PREFIX):
        raise HTTPException(status_code=204, detail=f"Ignored prefix: {object_id}")

    if not bucket or not object_id:
        raise HTTPException(status_code=400, detail="Missing bucket/object in event")

    return bucket, object_id, generation, {
        "attributes": attrs,
        "payloadFormat": payload_format,
        "payload": payload,
    }


def _download_exact_generation(bucket_name: str, object_id: str, generation: Optional[int]) -> bytes:
    """
    Download the object bytes, pinning to a specific generation when provided.
    """
    client = get_storage()
    bucket = client.bucket(bucket_name)
    if generation is not None:
        blob = storage.Blob(name=object_id, bucket=bucket, generation=generation)
        # Guard on the expected generation for strictness (safe if server supports it).
        return blob.download_as_bytes(if_generation_match=generation)  # type: ignore[arg-type]
    else:
        # Fallback: live version (not ideal if multiple writes happen quickly)
        blob = bucket.blob(object_id)
        return blob.download_as_bytes()


@app.get("/health")
def health():
    return {"status": "ok", "component": COMPONENT_NAME}


@app.post("/")  # Pub/Sub push target
async def pubsub_push(request: Request):
    # Optional: Verify OIDC token if you also configured Cloud Run to allow unauthenticated
    # or you want to double-check audience/issuer. If your service requires auth,
    # Cloud Run will already enforce it before reaching the app.
    await verify_pubsub_jwt_if_required(request)

    try:
        body = await request.json()
    except Exception:
        # If you enabled "payload unwrapping", body might be raw bytes; treat as no-op here.
        raise HTTPException(status_code=400, detail="Expected JSON body from Pub/Sub (wrapped).")

    try:
        bucket, object_id, generation, raw = _extract_event(body)
    except HTTPException as e:
        # 2xx acknowledges the message. Return 204 for "ignored" to avoid retries.
        if 200 <= e.status_code < 300:
            return Response(status_code=e.status_code)
        raise

    # Idempotency key (store/consult in your DB in future step)
    idem_key = f"{bucket}/{object_id}#{generation if generation is not None else 'live'}"
    logger.info(json_dumps({
        "msg": "event_received",
        "component": COMPONENT_NAME,
        "bucket": bucket,
        "object": object_id,
        "generation": generation,
        "idem_key": idem_key,
    }))

    # 1) Read object (by generation when available)
    try:
        content_bytes = _download_exact_generation(bucket, object_id, generation)
    except Exception as e:
        logger.exception("download_failed")
        # Non-2xx => Pub/Sub will retry
        raise HTTPException(status_code=500, detail=f"Download failed: {e}")

    # 2) Process
    try:
        # TO DO: Pass the content as filename instead of bytes
        result = await process_file(
            content=content_bytes,
            context={
                "bucket": bucket,
                "object": object_id,
                "generation": generation,
                "component": COMPONENT_NAME,
                "raw_event": raw,
            }
        )
    except Exception as e:
        logger.exception("processing_failed")
        raise HTTPException(status_code=500, detail=f"Processing failed: {e}")

    # 3) (Optional) Write output next to source in a component-specific prefix
    try:
        if OUTPUT_PREFIX:
            out_name = f"{OUTPUT_PREFIX}{object_id}.gen{generation if generation is not None else 'live'}.json"
            client = get_storage()
            bucket_ref = client.bucket(bucket)
            out_blob = bucket_ref.blob(out_name)
            out_blob.upload_from_string(
                data=json_dumps({"result": result, "source": idem_key}),
                content_type="application/json",
            )
            logger.info(json_dumps({"msg": "output_written", "uri": f"gs://{bucket}/{out_name}"}))
    except Exception:
        logger.exception("output_write_failed")
        raise HTTPException(status_code=500, detail="Output write failed")

    # Return 204 (no body) to ack push message immediately.
    return Response(status_code=204)
