# app/utils.py
import json
import os
from typing import Any

from fastapi import Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

# Toggle with env; when Cloud Run requires authentication, external verification is optional.
REQUIRE_JWT = os.getenv("REQUIRE_JWT", "false").lower() in {"1", "true", "yes"}
# If you set a custom audience in your subscription's OIDC token, put it here.
PUBSUB_ALLOWED_AUDIENCE = os.getenv("PUBSUB_ALLOWED_AUDIENCE")  # defaults to URL when unset


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


async def verify_pubsub_jwt_if_required(request: Request) -> None:
    if not REQUIRE_JWT:
        return
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise Exception("Missing Bearer token")

    token = auth.split(" ", 1)[1]
    req = google_requests.Request()
    # Audience: by default Pub/Sub sets aud to the push endpoint URL unless overridden.
    # If you configured a custom audience, set PUBSUB_ALLOWED_AUDIENCE accordingly.
    audience = PUBSUB_ALLOWED_AUDIENCE or str(request.url)
    claims = id_token.verify_oauth2_token(token, req, audience=audience)
    # Optionally, you could assert issuer or other claims here.
    # Typical Google-signed ID tokens have iss 'https://accounts.google.com'.
