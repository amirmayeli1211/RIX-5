from fastapi.testclient import TestClient
import json
from pathlib import Path
import xray_agent as agent


def test_agent_persists_add_remove_and_restore(tmp_path, monkeypatch):
    token = "A" * 64
    state_file = tmp_path / "inbounds.json"
    live_tags = set()
    commands = []
    inbound = {
        "tag": "rix-0123456789abcdef01234567",
        "listen": "0.0.0.0",
        "port": 20000,
        "protocol": "vless",
        "settings": {"clients": [{"id": "00000000-0000-4000-8000-000000000001"}], "decryption": "none"},
    }
    monkeypatch.setattr(agent, "AGENT_TOKEN", token)
    monkeypatch.setattr(agent, "STATE_PATH", state_file)
    monkeypatch.setattr(agent, "STATE", {})
    monkeypatch.setattr(agent, "PORT_START", 20000)
    monkeypatch.setattr(agent, "PORT_END", 20100)
    monkeypatch.setattr(agent, "_active_tags", lambda: set(live_tags))

    def fake_run(args, config=None):
        commands.append((args, config))
        if args[0] == "adi" and config:
            live_tags.add(config["tag"])
            assert "inbounds" not in config
        elif args[0] == "rmi":
            live_tags.discard(args[-1])
        return "{}"

    monkeypatch.setattr(agent, "_run", fake_run)
    with TestClient(agent.app) as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/v1/inbounds", json={"inbound": inbound}, headers=headers)
        assert response.status_code == 200
        tag = inbound["tag"]
        assert tag in live_tags
        assert state_file.exists()

        # Retry after a request timeout should be idempotent.
        response = client.post("/v1/inbounds", json={"inbound": inbound}, headers=headers)
        assert response.status_code == 200
        assert response.json()["already_active"] is True

        # Simulate Xray restart: API state is empty, Agent restores saved inbound.
        live_tags.clear()
        agent._reconcile_once()
        assert tag in live_tags

        response = client.delete(f"/v1/inbounds/{tag}", headers=headers)
        assert response.status_code == 200
        assert tag not in live_tags
        assert tag not in agent.STATE
        assert agent._load_state() == {}


def test_agent_rejects_unauthorized_request(monkeypatch):
    monkeypatch.setattr(agent, "AGENT_TOKEN", "B" * 64)
    with TestClient(agent.app) as client:
        r = client.get("/v1/status", headers={"Authorization": "Bearer " + "C" * 64})
        assert r.status_code == 401


def test_agent_rejects_malformed_protocol_payload(monkeypatch):
    token = "D" * 64
    monkeypatch.setattr(agent, "AGENT_TOKEN", token)
    monkeypatch.setattr(agent, "_active_tags", lambda: set())
    with TestClient(agent.app) as client:
        response = client.post(
            "/v1/inbounds",
            headers={"Authorization": "Bearer " + token},
            json={"inbound": {
                "tag": "rix-0123456789abcdef01234567",
                "listen": "0.0.0.0", "port": 20000, "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
            }},
        )
    assert response.status_code == 400
    assert "exactly one valid client" in response.text


def test_agent_cli_receives_single_inbound_object(tmp_path, monkeypatch):
    inbound = {
        "tag": "rix-0123456789abcdef01234567",
        "listen": "0.0.0.0", "port": 20000, "protocol": "vless",
        "settings": {"clients": [{"id": "00000000-0000-4000-8000-000000000001"}], "decryption": "none"},
    }
    captured = {}

    class Result:
        stdout = "ok"
        stderr = ""
        returncode = 0

    def fake_run(command, **kwargs):
        captured["command"] = command
        config_file = Path(command[-1])
        captured["payload"] = json.loads(config_file.read_text(encoding="utf-8"))
        return Result()

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    agent._run(["adi", "--server=127.0.0.1:10085"], inbound)
    assert captured["payload"] == inbound
    assert "inbounds" not in captured["payload"]


def test_status_exposes_auto_setup_values_only_after_bearer_auth(monkeypatch):
    token = "E" * 64
    monkeypatch.setattr(agent, "AGENT_TOKEN", token)
    monkeypatch.setattr(agent, "_active_tags", lambda: set())
    monkeypatch.setattr(agent, "REALITY_PRIVATE_KEY", "private-example")
    monkeypatch.setattr(agent, "REALITY_PUBLIC_KEY", "public-example")
    monkeypatch.setattr(agent, "REALITY_SHORT_ID", "ab12cd34")
    monkeypatch.setattr(agent, "REALITY_SNI", "www.microsoft.com")
    monkeypatch.setattr(agent, "NODE_DOMAIN", "vpn.example.com")
    monkeypatch.setattr(agent, "TLS_CERT_PATH", "/etc/rix-storm/tls/fullchain.pem")
    monkeypatch.setattr(agent, "TLS_KEY_PATH", "/etc/rix-storm/tls/privkey.pem")
    with TestClient(agent.app) as client:
        denied = client.get("/v1/status")
        assert denied.status_code == 401
        response = client.get("/v1/status", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["reality_private_key"] == "private-example"
    assert payload["reality_public_key"] == "public-example"
    assert payload["reality_short_id"] == "ab12cd34"
    assert payload["node_domain"] == "vpn.example.com"
    assert payload["tls_key_path"] == "/etc/rix-storm/tls/privkey.pem"
