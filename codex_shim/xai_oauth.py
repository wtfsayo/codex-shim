from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.parse import urlencode


DEFAULT_XAI_OAUTH_BASE_URL = "https://api.x.ai/v1"
XAI_OAUTH_DISCOVERY_URL = "https://auth.x.ai/.well-known/openid-configuration"
XAI_OAUTH_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
XAI_OAUTH_ISSUER = "https://auth.x.ai"
XAI_ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 3600


class XAIAuthError(RuntimeError):
    pass


def resolve_xai_oauth_runtime_credentials() -> dict[str, str]:
    """Resolve an xAI OAuth bearer from ~/.grok first, then ~/.hermes."""
    errors: list[str] = []
    for auth_path, store, state, source in _iter_auth_states():
        try:
            return _resolve_auth_state(auth_path, store, state, source)
        except Exception as exc:
            errors.append(f"{auth_path}: {exc}")
            continue
    detail = "; ".join(errors)
    suffix = f" ({detail})" if detail else ""
    raise XAIAuthError(f"No valid xAI OAuth tokens found in ~/.grok or ~/.hermes{suffix}.")


def _resolve_auth_state(
    auth_path: Path,
    store: dict[str, Any],
    state: dict[str, Any],
    source: tuple[str, int | str | None],
) -> dict[str, str]:
    tokens = dict(state.get("tokens") or {})
    access_token = str(tokens.get("access_token") or "").strip()
    refresh_token = str(tokens.get("refresh_token") or "").strip()
    if not access_token or not refresh_token:
        raise XAIAuthError("No xAI OAuth tokens found. Run `grok login` or `hermes auth add xai-oauth`.")

    if _access_token_is_expiring(access_token, XAI_ACCESS_TOKEN_REFRESH_SKEW_SECONDS):
        discovery = dict(state.get("discovery") or {})
        token_endpoint = str(discovery.get("token_endpoint") or "").strip()
        if not token_endpoint:
            token_endpoint = _discover_token_endpoint()
        refreshed = _refresh_tokens(refresh_token, token_endpoint)
        tokens.update(refreshed)
        access_token = str(tokens.get("access_token") or "").strip()
        state["tokens"] = tokens
        state["last_refresh"] = _utc_now()
        state.setdefault("auth_mode", "oauth_pkce")
        state["discovery"] = {"token_endpoint": token_endpoint}
        _write_xai_state(auth_path, store, state, source)

    return {
        "api_key": access_token,
        "base_url": _validated_base_url(
            os.environ.get("HERMES_XAI_BASE_URL", "").strip()
            or os.environ.get("XAI_BASE_URL", "").strip()
            or DEFAULT_XAI_OAUTH_BASE_URL
        ),
    }


def _iter_auth_states() -> list[tuple[Path, dict[str, Any], dict[str, Any], tuple[str, int | str | None]]]:
    states: list[tuple[Path, dict[str, Any], dict[str, Any], tuple[str, int | str | None]]] = []
    for path, store_name in _auth_paths():
        try:
            store = _read_auth_store(path)
            state, source = _xai_state_from_store(store, store_name)
        except XAIAuthError as exc:
            continue
        tokens = state.get("tokens") if isinstance(state, dict) else None
        if isinstance(tokens, dict) and tokens.get("access_token") and tokens.get("refresh_token"):
            states.append((path, store, state, source))
    return states


def _auth_paths() -> list[tuple[Path, str]]:
    grok_home = os.environ.get("GROK_HOME", "").strip()
    grok_path = Path(grok_home).expanduser() / "auth.json" if grok_home else Path.home() / ".grok" / "auth.json"
    return [(grok_path, "grok"), (_hermes_auth_path(), "hermes")]


def _hermes_auth_path() -> Path:
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    if hermes_home:
        return Path(hermes_home).expanduser() / "auth.json"
    return Path.home() / ".hermes" / "auth.json"


def _read_auth_store(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise XAIAuthError(f"Hermes auth store not found at {path}. Run `hermes auth add xai-oauth`.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise XAIAuthError(f"Could not read Hermes auth store at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise XAIAuthError(f"Hermes auth store at {path} is not a JSON object.")
    return data


def _xai_state_from_store(store: dict[str, Any], store_name: str) -> tuple[dict[str, Any], tuple[str, int | str | None]]:
    if store_name == "grok":
        state, key = _grok_state_from_store(store)
        if _has_tokens(state):
            return state, ("grok", key)

    providers = store.get("providers")
    if isinstance(providers, dict):
        state = providers.get("xai-oauth")
        if _has_tokens(state):
            return dict(state), ("providers", None)

    pool = store.get("credential_pool")
    entries = pool.get("xai-oauth") if isinstance(pool, dict) else None
    if isinstance(entries, list):
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            access_token = str(entry.get("access_token") or entry.get("runtime_api_key") or "").strip()
            refresh_token = str(entry.get("refresh_token") or "").strip()
            if access_token and refresh_token:
                state = {
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": str(entry.get("token_type") or "Bearer"),
                    },
                    "last_refresh": entry.get("last_refresh"),
                    "auth_mode": "oauth_pkce",
                }
                if entry.get("discovery"):
                    state["discovery"] = entry.get("discovery")
                return state, ("credential_pool", index)
    return {}, ("missing", None)


def _grok_state_from_store(store: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    preferred_key = f"{XAI_OAUTH_ISSUER}::{XAI_OAUTH_CLIENT_ID}"
    entries: list[tuple[str, Any]] = []
    if preferred_key in store:
        entries.append((preferred_key, store[preferred_key]))
    entries.extend((key, value) for key, value in store.items() if key != preferred_key)

    for key, value in entries:
        if not isinstance(value, dict):
            continue
        issuer = str(value.get("oidc_issuer") or "").strip().rstrip("/")
        client_id = str(value.get("oidc_client_id") or "").strip()
        if issuer and issuer != XAI_OAUTH_ISSUER:
            continue
        if client_id and client_id != XAI_OAUTH_CLIENT_ID:
            continue
        access_token = str(value.get("key") or value.get("access_token") or "").strip()
        refresh_token = str(value.get("refresh_token") or "").strip()
        if not access_token or not refresh_token:
            continue
        state = {
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": str(value.get("token_type") or "Bearer"),
            },
            "last_refresh": value.get("last_refresh") or value.get("create_time"),
            "auth_mode": value.get("auth_mode") or "oauth_pkce",
            "discovery": {"token_endpoint": str(value.get("token_endpoint") or "").strip()}
            if value.get("token_endpoint")
            else {},
            "grok_record": dict(value),
        }
        return state, key
    return {}, None


def _has_tokens(value: Any) -> bool:
    tokens = value.get("tokens") if isinstance(value, dict) else None
    if not isinstance(tokens, dict):
        return False
    return bool(str(tokens.get("access_token") or "").strip() and str(tokens.get("refresh_token") or "").strip())


def _write_xai_state(path: Path, store: dict[str, Any], state: dict[str, Any], source: tuple[str, int | str | None]) -> None:
    kind, index = source
    if kind == "grok":
        key = index if isinstance(index, str) else f"{XAI_OAUTH_ISSUER}::{XAI_OAUTH_CLIENT_ID}"
        record = dict(state.get("grok_record") or store.get(key) or {})
        tokens = state.get("tokens") or {}
        record["key"] = tokens.get("access_token", "")
        record["refresh_token"] = tokens.get("refresh_token", "")
        record["auth_mode"] = record.get("auth_mode") or "oauth_pkce"
        record["oidc_issuer"] = record.get("oidc_issuer") or XAI_OAUTH_ISSUER
        record["oidc_client_id"] = record.get("oidc_client_id") or XAI_OAUTH_CLIENT_ID
        if tokens.get("expires_in") is not None:
            record["expires_at"] = _expires_at_from_seconds(tokens.get("expires_in"))
        record["last_refresh"] = state.get("last_refresh") or _utc_now()
        discovery = state.get("discovery") if isinstance(state.get("discovery"), dict) else {}
        if discovery.get("token_endpoint"):
            record["token_endpoint"] = discovery["token_endpoint"]
        store[key] = record
    elif kind == "credential_pool":
        pool = store.setdefault("credential_pool", {})
        entries = pool.setdefault("xai-oauth", [])
        if isinstance(entries, list) and isinstance(index, int) and index < len(entries):
            entry = entries[index]
            if isinstance(entry, dict):
                tokens = state.get("tokens") or {}
                entry["access_token"] = tokens.get("access_token", "")
                entry["refresh_token"] = tokens.get("refresh_token", "")
                entry["token_type"] = tokens.get("token_type", "Bearer")
                entry["last_refresh"] = state.get("last_refresh")
                entry["discovery"] = state.get("discovery") or {}
    else:
        providers = store.setdefault("providers", {})
        if isinstance(providers, dict):
            providers["xai-oauth"] = state

    tmp = path.with_suffix(path.suffix + ".codex-shim-tmp")
    tmp.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def _access_token_is_expiring(access_token: str, skew_seconds: int) -> bool:
    if "." not in access_token:
        return False
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8"))
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            return False
        return float(exp) <= (time.time() + max(0, int(skew_seconds)))
    except Exception:
        return False


def _expires_at_from_seconds(expires_in: Any) -> str:
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        seconds = 3600
    return datetime.fromtimestamp(time.time() + max(0, seconds), timezone.utc).isoformat().replace("+00:00", "Z")


def _discover_token_endpoint() -> str:
    req = Request(XAI_OAUTH_DISCOVERY_URL, headers={"Accept": "application/json"})
    with urlopen(req, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    endpoint = str(payload.get("token_endpoint") or "").strip()
    return _validate_xai_url(endpoint, "token_endpoint")


def _refresh_tokens(refresh_token: str, token_endpoint: str) -> dict[str, Any]:
    token_endpoint = _validate_xai_url(token_endpoint, "token_endpoint")
    data = urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": XAI_OAUTH_CLIENT_ID,
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    req = Request(
        token_endpoint,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise XAIAuthError("xAI token refresh did not return an access_token.")
    return {
        "access_token": access_token,
        "refresh_token": str(payload.get("refresh_token") or refresh_token).strip(),
        "id_token": str(payload.get("id_token") or "").strip(),
        "expires_in": payload.get("expires_in"),
        "token_type": str(payload.get("token_type") or "Bearer").strip() or "Bearer",
    }


def _validate_xai_url(value: str, field: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or (host != "x.ai" and not host.endswith(".x.ai")):
        raise XAIAuthError(f"Refusing non-xAI {field}: {value!r}")
    return value


def _validated_base_url(value: str) -> str:
    candidate = value.strip().rstrip("/") or DEFAULT_XAI_OAUTH_BASE_URL
    try:
        return _validate_xai_url(candidate, "base_url")
    except XAIAuthError:
        return DEFAULT_XAI_OAUTH_BASE_URL


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
