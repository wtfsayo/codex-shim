from __future__ import annotations

import json

from codex_shim import cli


def _settings(path):
    path.write_text(
        json.dumps(
            {
                "customModels": [
                    {
                        "model": "grok-composer-upstream",
                        "displayName": "Grok Composer",
                        "provider": "xai-oauth",
                        "baseUrl": "https://example.invalid/v1",
                        "apiKey": "oauth-token",
                    }
                ]
            }
        )
    )
    return path


def test_install_droid_config_preserves_non_shim_and_reuses_ids(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "chatgpt_passthrough_available", lambda: True)
    monkeypatch.setattr(cli, "chatgpt_passthrough_display_names", lambda: {"gpt-5.5": "GPT-5.5"})
    monkeypatch.setattr(cli, "cursor_passthrough_available", lambda: False)

    settings = _settings(tmp_path / "models.json")
    droid = tmp_path / "factory-settings.json"
    droid.write_text(
        json.dumps(
            {
                "customModels": [
                    {
                        "model": "local-existing",
                        "displayName": "Local Existing",
                        "baseUrl": "http://127.0.0.1:9999/v1",
                        "apiKey": "local-key",
                        "provider": "generic-chat-completion-api",
                        "id": "custom:local-existing-1",
                        "index": 1,
                    },
                    {
                        "model": "gpt-5.5",
                        "displayName": "GPT-5.5 (via Codex Shim)",
                        "baseUrl": "http://127.0.0.1:8765/v1",
                        "apiKey": "dummy",
                        "provider": "openai",
                        "id": "custom:gpt-5.5-7",
                        "index": 7,
                    },
                    {
                        "model": "stale-shim",
                        "displayName": "Stale",
                        "baseUrl": "http://127.0.0.1:8765/v1",
                        "apiKey": "dummy",
                        "provider": "openai",
                        "id": "custom:stale-shim-8",
                        "index": 8,
                    },
                ],
                "sessionDefaultSettings": {"model": "custom:gpt-5.5-7"},
                "modelFavorites": ["custom:gpt-5.5-7", "custom:stale-shim-8"],
            }
        )
    )

    code = cli.install_droid_config(settings, 8765, droid, model_slug="grok-composer-upstream")

    data = json.loads(droid.read_text())
    models = data["customModels"]
    by_model = {row["model"]: row for row in models}
    assert code == 0
    assert "local-existing" in by_model
    assert "stale-shim" not in by_model
    assert by_model["gpt-5.5"]["id"] == "custom:gpt-5.5-7"
    assert by_model["grok-composer-upstream"]["baseUrl"] == "http://127.0.0.1:8765/v1"
    assert by_model["grok-composer-upstream"]["generatedBy"] == cli.DROID_GENERATED_BY
    assert by_model["gpt-5.5"]["supportedReasoningEfforts"] == ["low", "medium", "high", "xhigh"]
    assert by_model["gpt-5.5"]["defaultReasoningEffort"] == "medium"
    assert by_model["grok-composer-upstream"]["supportedReasoningEfforts"] == ["off", "low", "medium", "high"]
    assert by_model["grok-composer-upstream"]["defaultReasoningEffort"] == "high"
    assert data["sessionDefaultSettings"]["model"] == by_model["grok-composer-upstream"]["id"]
    assert by_model["grok-composer-upstream"]["id"] in data["modelFavorites"]


def test_install_droid_config_can_skip_default_update(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "chatgpt_passthrough_available", lambda: True)
    monkeypatch.setattr(cli, "chatgpt_passthrough_display_names", lambda: {"gpt-5.5": "GPT-5.5"})
    monkeypatch.setattr(cli, "cursor_passthrough_available", lambda: False)

    settings = _settings(tmp_path / "models.json")
    droid = tmp_path / "factory-settings.json"
    droid.write_text(json.dumps({"sessionDefaultSettings": {"model": "gpt-5.5"}}))

    code = cli.install_droid_config(settings, 8765, droid, update_default=False)

    data = json.loads(droid.read_text())
    assert code == 0
    assert data["sessionDefaultSettings"]["model"] == "gpt-5.5"
    assert {row["model"] for row in data["customModels"]} == {"gpt-5.5", "grok-composer-upstream"}
