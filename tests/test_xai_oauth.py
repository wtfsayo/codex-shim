import base64
import json
import time

import pytest

from codex_shim.xai_oauth import resolve_xai_oauth_runtime_credentials


def _jwt(exp: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


def _write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def test_resolves_grok_auth_before_hermes(tmp_path, monkeypatch):
    monkeypatch.setenv("GROK_HOME", str(tmp_path / ".grok"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    future = int(time.time()) + 7200
    _write_json(
        tmp_path / ".grok" / "auth.json",
        {
            "https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828": {
                "key": _jwt(future),
                "refresh_token": "grok-refresh",
                "oidc_issuer": "https://auth.x.ai",
                "oidc_client_id": "b1a00492-073a-47ea-816f-4c329264a828",
            }
        },
    )
    _write_json(
        tmp_path / ".hermes" / "auth.json",
        {
            "providers": {
                "xai-oauth": {
                    "tokens": {
                        "access_token": _jwt(future),
                        "refresh_token": "hermes-refresh",
                    }
                }
            }
        },
    )

    creds = resolve_xai_oauth_runtime_credentials()

    assert creds["api_key"].endswith(".sig")
    grok_store = json.loads((tmp_path / ".grok" / "auth.json").read_text())
    assert creds["api_key"] == grok_store["https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828"]["key"]


def test_falls_back_to_hermes_when_grok_refresh_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GROK_HOME", str(tmp_path / ".grok"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    past = int(time.time()) - 60
    future = int(time.time()) + 7200
    _write_json(
        tmp_path / ".grok" / "auth.json",
        {
            "https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828": {
                "key": _jwt(past),
                "refresh_token": "bad-grok-refresh",
                "oidc_issuer": "https://auth.x.ai",
                "oidc_client_id": "b1a00492-073a-47ea-816f-4c329264a828",
            }
        },
    )
    hermes_access = _jwt(future)
    _write_json(
        tmp_path / ".hermes" / "auth.json",
        {
            "providers": {
                "xai-oauth": {
                    "tokens": {
                        "access_token": hermes_access,
                        "refresh_token": "hermes-refresh",
                    }
                }
            }
        },
    )

    def fail_grok_refresh(refresh_token, _token_endpoint):
        if refresh_token == "bad-grok-refresh":
            raise RuntimeError("refresh failed")
        pytest.fail("Hermes should not refresh because its token is still valid")

    monkeypatch.setattr("codex_shim.xai_oauth._discover_token_endpoint", lambda: "https://auth.x.ai/oauth/token")
    monkeypatch.setattr("codex_shim.xai_oauth._refresh_tokens", fail_grok_refresh)

    creds = resolve_xai_oauth_runtime_credentials()

    assert creds["api_key"] == hermes_access
