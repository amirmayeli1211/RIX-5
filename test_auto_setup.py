from pathlib import Path
import pytest
from security import decrypt_secret
import main


def test_new_node_gets_automatic_agent_and_tls_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    node = main._node_from_form({
        "name": "DE-01",
        "host": "vpn.example.com",
        "proxy_ip": "",
        "port_start": "20000",
        "port_end": "20100",
        "enabled": "true",
    })
    assert node.agent_url == "https://vpn.example.com"
    assert len(decrypt_secret(node.agent_token_encrypted)) >= 32
    assert node.port_start == 20000 and node.port_end == 20100
    assert node.tls_sni == "vpn.example.com"
    assert node.tls_cert_path == "/etc/rix-storm/tls/fullchain.pem"
    assert node.tls_key_path == "/etc/rix-storm/tls/privkey.pem"
    assert node.reality_sni == "www.microsoft.com"


def test_new_node_requires_domain_for_automatic_https(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="دامنهٔ عمومی"):
        main._node_from_form({"name": "IP-only", "host": "203.0.113.9"})


def test_all_jinja_templates_compile():
    for name in ("base.html", "nodes.html", "clients.html", "dashboard.html", "login.html", "subscription.html"):
        main.templates.env.get_template(name)


def test_bootstrap_assets_are_served():
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    installer = client.get("/install-node.sh")
    agent_source = client.get("/xray-agent.py")
    assert installer.status_code == 200
    assert "one-command setup" in installer.text
    assert agent_source.status_code == 200
    assert "rix-storm-xray-agent" in agent_source.text
