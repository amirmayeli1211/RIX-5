"""Authenticated API bridge that provisions persistent dynamic inbounds on Xray-core.

This agent belongs on the real VPN VPS, not on the Railway web service. Protect its
HTTP API with HTTPS and a long random AGENT_TOKEN. Xray's gRPC API stays on loopback.
"""
from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("rix-storm-agent")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "").strip()
XRAY_API_ADDR = os.getenv("XRAY_API_ADDR", "127.0.0.1:10085").strip()
XRAY_BIN = os.getenv("XRAY_BIN", "/opt/rix-storm-agent/xray")
PORT_START = int(os.getenv("AGENT_PORT_START", "20000"))
PORT_END = int(os.getenv("AGENT_PORT_END", "20100"))
STATE_PATH = Path(os.getenv("AGENT_STATE_PATH", "/opt/rix-storm-agent/inbounds.json"))
RECONCILE_SECONDS = max(10, int(os.getenv("AGENT_RECONCILE_SECONDS", "30")))
NODE_DOMAIN = os.getenv("NODE_DOMAIN", "").strip()
TLS_CERT_PATH = os.getenv("TLS_CERT_PATH", "").strip()
TLS_KEY_PATH = os.getenv("TLS_KEY_PATH", "").strip()
REALITY_PRIVATE_KEY = os.getenv("REALITY_PRIVATE_KEY", "").strip()
REALITY_PUBLIC_KEY = os.getenv("REALITY_PUBLIC_KEY", "").strip()
REALITY_SHORT_ID = os.getenv("REALITY_SHORT_ID", "").strip()
REALITY_SNI = os.getenv("REALITY_SNI", "www.microsoft.com").strip()
ALLOWED_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
STATE_LOCK = threading.RLock()
RESTORE_TASK: asyncio.Task | None = None


def _load_state() -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        inbounds = raw.get("inbounds", {}) if isinstance(raw, dict) else {}
        if not isinstance(inbounds, dict):
            raise ValueError("state inbounds must be an object")
        clean: dict[str, dict[str, Any]] = {}
        for tag, inbound in inbounds.items():
            if (isinstance(tag, str) and re.fullmatch(r"rix-[a-z0-9-]{6,90}", tag)
                    and isinstance(inbound, dict) and inbound.get("tag") == tag
                    and inbound.get("protocol") in ALLOWED_PROTOCOLS):
                clean[tag] = inbound
        return clean
    except FileNotFoundError:
        return {}
    except Exception:
        log.exception("Could not read agent state at %s; no inbound state was loaded", STATE_PATH)
        return {}


STATE: dict[str, dict[str, Any]] = _load_state()


class InboundBody(BaseModel):
    inbound: dict[str, Any]


def _auth(value: str | None) -> None:
    if not AGENT_TOKEN or len(AGENT_TOKEN) < 32:
        raise HTTPException(503, "Agent is not configured with a strong AGENT_TOKEN.")
    sent = (value or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(sent, AGENT_TOKEN):
        raise HTTPException(401, "Unauthorized")


def _run(args: list[str], config: dict | None = None) -> str:
    config_path = None
    try:
        if config is not None:
            # `xray api adi` accepts one InboundDetourConfig object, not a full
            # top-level Xray config with an `inbounds` array. Passing the latter
            # makes valid-looking users fail at runtime.
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
                json.dump(config, f, ensure_ascii=False, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
                os.chmod(f.name, 0o600)
                config_path = f.name
        cmd = [XRAY_BIN, "api", *args]
        if config_path:
            cmd.append(config_path)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=25, check=False)
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode != 0:
            raise HTTPException(502, output[-900:] or "Xray API returned an error")
        return output[-900:]
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "Xray API timeout") from exc
    except FileNotFoundError as exc:
        raise HTTPException(503, "Xray binary is missing; install the official Xray-core release.") from exc
    finally:
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass


def _active_tags() -> set[str]:
    """Query live inbound tags using Xray's CLI (no public API exposure)."""
    try:
        result = subprocess.run([XRAY_BIN, "api", "lsi", f"--server={XRAY_API_ADDR}"],
                                capture_output=True, text=True, timeout=12, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "Xray API timeout while listing inbounds") from exc
    except FileNotFoundError as exc:
        raise HTTPException(503, "Xray binary is missing") from exc
    if result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr).strip()[-600:]
        raise HTTPException(502, detail or "Xray API is not reachable")
    try:
        payload = json.loads(result.stdout)
        inbounds = payload.get("inbounds", []) if isinstance(payload, dict) else []
        if not isinstance(inbounds, list):
            raise ValueError("Unexpected Xray inbound list")
        return {str(item.get("tag")) for item in inbounds if isinstance(item, dict) and item.get("tag")}
    except (ValueError, json.JSONDecodeError):
        # Newer CLI builds support --isOnlyTags. Keep a fallback for output-format differences.
        result = subprocess.run([XRAY_BIN, "api", "lsi", f"--server={XRAY_API_ADDR}", "--isOnlyTags=true"],
                                capture_output=True, text=True, timeout=12, check=False)
        if result.returncode != 0:
            raise HTTPException(502, "Unable to read active Xray inbound tags")
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _save_state() -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=STATE_PATH.parent,
                                         prefix=".inbounds-", suffix=".tmp", delete=False) as f:
            temp_path = Path(f.name)
            os.chmod(temp_path, 0o600)
            json.dump({"version": 1, "inbounds": STATE}, f, ensure_ascii=False, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, STATE_PATH)
        try:
            os.chmod(STATE_PATH, 0o600)
        except OSError:
            pass
    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def _reconcile_once() -> None:
    with STATE_LOCK:
        if not STATE:
            return
        live = _active_tags()
        for tag, inbound in list(STATE.items()):
            if tag in live:
                continue
            try:
                _run(["adi", f"--server={XRAY_API_ADDR}"], inbound)
                live.add(tag)
                log.info("Restored Xray inbound %s after Xray restart", tag)
            except Exception:
                log.exception("Unable to restore Xray inbound %s; will retry", tag)


async def _reconcile_loop() -> None:
    # Xray may start after this service; retry rather than losing saved inbounds.
    await asyncio.sleep(5)
    while True:
        try:
            await asyncio.to_thread(_reconcile_once)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Xray reconciliation failed; will retry in %s seconds", RECONCILE_SECONDS)
        await asyncio.sleep(RECONCILE_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global RESTORE_TASK, STATE
    with STATE_LOCK:
        STATE = _load_state()
    RESTORE_TASK = asyncio.create_task(_reconcile_loop())
    try:
        yield
    finally:
        if RESTORE_TASK and not RESTORE_TASK.done():
            RESTORE_TASK.cancel()
            try:
                await RESTORE_TASK
            except asyncio.CancelledError:
                pass
        RESTORE_TASK = None


app = FastAPI(title="RIX STORM Xray Agent", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "service": "rix-storm-xray-agent"}


@app.get("/v1/status")
def status(authorization: str | None = Header(default=None)):
    _auth(authorization)
    with STATE_LOCK:
        active = sorted(_active_tags())
        managed = sorted(STATE.keys())
    return {"ok": True, "api": XRAY_API_ADDR, "managed_inbounds": len(managed),
            "active_managed_inbounds": sum(1 for tag in managed if tag in active),
            "active_tags": [tag for tag in active if tag.startswith("rix-")],
            # Returned only after bearer-token authentication; the panel uses these
            # values to configure TLS and Reality without manual key copying.
            "node_domain": NODE_DOMAIN,
            "tls_cert_path": TLS_CERT_PATH,
            "tls_key_path": TLS_KEY_PATH,
            "reality_private_key": REALITY_PRIVATE_KEY,
            "reality_public_key": REALITY_PUBLIC_KEY,
            "reality_short_id": REALITY_SHORT_ID,
            "reality_sni": REALITY_SNI}


@app.post("/v1/inbounds")
def add_inbound(body: InboundBody, authorization: str | None = Header(default=None)):
    _auth(authorization)
    inbound = json.loads(json.dumps(body.inbound))
    tag = str(inbound.get("tag", ""))
    protocol = str(inbound.get("protocol", ""))
    try:
        port = int(inbound.get("port", 0))
    except (ValueError, TypeError):
        port = 0
    if not re.fullmatch(r"rix-[a-z0-9-]{6,90}", tag):
        raise HTTPException(400, "Invalid inbound tag")
    if protocol not in ALLOWED_PROTOCOLS:
        raise HTTPException(400, "Protocol is not supported by this Xray agent")
    if not PORT_START <= port <= PORT_END:
        raise HTTPException(400, f"Port must be between {PORT_START} and {PORT_END}")
    if inbound.get("listen") not in ("0.0.0.0", "::", "127.0.0.1", None):
        raise HTTPException(400, "Invalid listen address")
    inbound["listen"] = "0.0.0.0"
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        raise HTTPException(400, "Inbound settings must be an object")
    if inbound.get("protocol") in {"vless", "vmess", "trojan"}:
        clients = settings.get("clients")
        if not isinstance(clients, list) or len(clients) != 1 or not isinstance(clients[0], dict):
            raise HTTPException(400, "Inbound must contain exactly one valid client")
        credential_key = "password" if protocol == "trojan" else "id"
        if not isinstance(clients[0].get(credential_key), str) or not clients[0][credential_key]:
            raise HTTPException(400, f"Inbound is missing client {credential_key}")
    elif protocol == "shadowsocks":
        if not settings.get("method") or not settings.get("password"):
            raise HTTPException(400, "Shadowsocks inbound requires method and password")
    stream = inbound.get("streamSettings")
    if stream is not None and not isinstance(stream, dict):
        raise HTTPException(400, "streamSettings must be an object")
    with STATE_LOCK:
        live = _active_tags()
        saved = STATE.get(tag)
        if tag in live:
            if saved == inbound:
                return {"ok": True, "tag": tag, "port": port, "already_active": True}
            raise HTTPException(409, "An inbound with this tag already exists; remove it or use another tag.")
        try:
            _run(["adi", f"--server={XRAY_API_ADDR}"], inbound)
            STATE[tag] = inbound
            try:
                _save_state()
            except Exception as exc:
                STATE.pop(tag, None)
                try:
                    _run(["rmi", f"--server={XRAY_API_ADDR}", tag])
                except Exception:
                    log.exception("Could not roll back inbound %s after state write failure", tag)
                raise HTTPException(507, "Could not securely persist Agent state; inbound was rolled back if possible.") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(500, "Unable to save Agent state") from exc
    return {"ok": True, "tag": tag, "port": port}


@app.delete("/v1/inbounds/{tag}")
def remove_inbound(tag: str, authorization: str | None = Header(default=None)):
    _auth(authorization)
    if not re.fullmatch(r"rix-[a-z0-9-]{6,90}", tag):
        raise HTTPException(400, "Invalid inbound tag")
    with STATE_LOCK:
        live = _active_tags()
        old_inbound = STATE.get(tag)
        if tag in live:
            _run(["rmi", f"--server={XRAY_API_ADDR}", tag])
        STATE.pop(tag, None)
        try:
            _save_state()
        except Exception as exc:
            # Keep database, disk state and live Xray as consistent as possible on disk errors.
            if old_inbound is not None:
                STATE[tag] = old_inbound
                if tag in live:
                    try:
                        _run(["adi", f"--server={XRAY_API_ADDR}"], old_inbound)
                    except Exception:
                        log.exception("Could not roll back inbound %s after state write failure", tag)
            raise HTTPException(507, "Could not securely update Agent state; operation was rolled back if possible.") from exc
    return {"ok": True, "tag": tag}
