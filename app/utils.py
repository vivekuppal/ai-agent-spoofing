# app/utils.py
import json
import os
from typing import Any
from functools import lru_cache
from typing import Optional, Callable
import ipaddress
from ipwhois import IPWhois

from fastapi import Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token


# Toggle with env; when Cloud Run requires authentication, external verification is optional.
REQUIRE_JWT = os.getenv("REQUIRE_JWT", "false").lower() in {"1", "true", "yes"}
# If you set a custom audience in your subscription's OIDC token, put it here.
PUBSUB_ALLOWED_AUDIENCE = os.getenv("PUBSUB_ALLOWED_AUDIENCE")  # defaults to URL when unset


try:
    # Optional dependency: pip install google-cloud-secret-manager
    from google.cloud import secretmanager  # type: ignore
    _HAS_GSM = True
except Exception:
    _HAS_GSM = False


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
    # Optionally, assert issuer or other claims here.
    # Typical Google-signed ID tokens have iss 'https://accounts.google.com'.


class SecretNotFound(Exception):
    """Raised when no source (env, GSM, default) yields a value."""


@lru_cache(maxsize=256)
def get_rdap_info(ip_address: str) -> dict:
    """
    Fetch RDAP information for an IPv4 or IPv6 address.

    Args:
        ip_address (str): The IP address (IPv4 or IPv6).

    Returns:
        dict: RDAP information, or error message if query fails.
    """
    try:
        # Validate the IP address
        ipaddress.ip_address(ip_address)

        obj = IPWhois(ip_address)
        rdap_result = obj.lookup_rdap(depth=1)
        return rdap_result
    except ValueError:
        return {"error": f"Invalid IP address format: {ip_address}"}
    except Exception as e:
        return {"error": str(e)}


def get_country_from_rdap(rdap_info: dict) -> str:
    """
    Extract the country code from RDAP information.

    Args:
        rdap_info (dict): RDAP information dictionary.

    Returns:
        str: Country code (e.g. 'US', 'DE'), or error message.
    """

    # First, try top-level ASN country code
    country = rdap_info.get("asn_country_code")
    if country:
        return country

    # Fallback: sometimes in network objects
    try:
        return rdap_info["network"]["country"]
    except KeyError:
        return "Country not found"


@lru_cache(maxsize=256)
def _fetch_from_gsm(
    secret_name: str,
    project_id: str,
    version: str = "latest",
) -> Optional[str]:
    """
    Fetch a secret from Google Cloud Secret Manager.

    Accepts either:
      - plain name (e.g., "db_password") + project_id
      - full resource path (e.g., "projects/123/secrets/db_password/versions/latest")

    Returns the string value, or None if unavailable.

    Use of @lru_cache allows efficient reuse of the secret value
    across multiple calls without re-fetching from GSM. It does mean
    that when the secret changes, the cache will not automatically update.
    If you need to refresh, clear the cache with:
    """
    if not _HAS_GSM:
        return None

    # Build resource name
    if "/" in secret_name and secret_name.startswith("projects/"):
        resource = secret_name
    else:
        if not project_id:
            return None  # cannot build a resource without project_id
        resource = f"projects/{project_id}/secrets/{secret_name}/versions/{version}"

    try:
        client = secretmanager.SecretManagerServiceClient()
        resp = client.access_secret_version(name=resource)
        payload = resp.payload.data.decode("utf-8")
        return payload
    except Exception:
        # Any error (no ADC, permission denied, not found, etc.) -> None
        return None


def clear_gsm_cache(secret_name: Optional[str] = None,
                    project_id: Optional[str] = None) -> None:
    """
    Clear the cached GSM secrets.
    Useful if you know a secret has changed and you want to force a reload.
    """
    _fetch_from_gsm.cache_clear(secret_name, project_id)


def get_secret(
    *,
    env_var: Optional[str] = None,
    secret_name: Optional[str] = None,
    default: Optional[str] = None,
    project_id: Optional[str] = None,
    version: str = "latest",
    transform: Optional[Callable[[str], str]] = None,
    required: bool = False,
) -> Optional[str]:
    """
    Resolve a secret with graceful fallbacks.

    Resolution order:
      1) Environment variable (env_var)
      2) Google Cloud Secret Manager (secret_name [+ project_id] or full resource)
      3) default

    Args:
        env_var: Name of the environment variable to check.
        secret_name: GSM secret name or full resource path
                    ("projects/.../secrets/.../versions/...").
        default: Inline fallback value.
        project_id: GCP project ID (needed if secret_name is not a full path).
        version: GSM version to read (default "latest").
        transform: Optional post-processor, e.g., str.strip or json.loads.
        required: If True, raise SecretNotFound when nothing is found.

    Returns:
        The resolved secret string (possibly transformed), or None.

    Raises:
        SecretNotFound: if required=True and no value is found.
    """
    # 1) env
    if env_var:
        val = os.getenv(env_var)
        if val not in (None, ""):
            return transform(val) if transform else val

    # 2) GSM
    if secret_name:
        val = _fetch_from_gsm(secret_name, project_id=project_id,
                              version=version)
        if val not in (None, ""):
            return transform(val) if transform else val

    # 3) default
    if default not in (None, ""):
        return transform(default) if transform else default

    if required:
        sources = []
        if env_var:
            sources.append(f"env:{env_var}")
        if secret_name:
            sources.append(f"gsm:{secret_name}")
        raise SecretNotFound(f"No secret found from {', '.join(sources)} and no default provided.")

    return None


# -----------------------
# Example usages
# -----------------------
if __name__ == "__main__":
    # Example 1: Prefer ENV, then GSM "db_password" in project "my-prod", else "changeme"
    db_password = get_secret(
        env_var="DB_PASSWORD",
        secret_name="db_password",
        project_id="my-prod",
        default="changeme",
        required=True,  # raise if all fail
        transform=str.strip
    )
    print("DB password length:", len(db_password))

    # Example 2: Using a full GSM resource path (no project_id needed)
    api_key = get_secret(
        env_var="API_KEY",
        secret_name="projects/1234567890/secrets/api_key/versions/latest",
        default=None,  # no default; return None if missing (or raise if required=True)
    )
    print("API key present:", bool(api_key))
