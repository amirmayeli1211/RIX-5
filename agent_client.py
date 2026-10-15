from __future__ import annotations
import requests
from security import decrypt_secret

class AgentError(RuntimeError):
    pass

def _url(node, path: str) -> str:
    base = (node.agent_url or "").strip().rstrip("/")
    if not base.startswith("https://"):
        raise AgentError("آدرس Agent باید با HTTPS شروع شود.")
    return base + path

def add_inbound(node, inbound: dict) -> None:
    token = decrypt_secret(node.agent_token_encrypted)
    try:
        r = requests.post(_url(node, "/v1/inbounds"), json={"inbound": inbound},
                          headers={"Authorization": f"Bearer {token}"}, timeout=(5, 25))
    except requests.RequestException as exc:
        raise AgentError("اتصال به Agent سرور برقرار نشد؛ آدرس و وضعیت سرور را بررسی کن.") from exc
    if r.status_code >= 300:
        try: detail = r.json().get("detail", "")
        except Exception: detail = r.text[:300]
        raise AgentError(f"Xray کاربر را نپذیرفت: {detail or r.status_code}")

def remove_inbound(node, tag: str) -> None:
    token = decrypt_secret(node.agent_token_encrypted)
    try:
        r = requests.delete(_url(node, f"/v1/inbounds/{tag}"),
                            headers={"Authorization": f"Bearer {token}"}, timeout=(5, 25))
    except requests.RequestException as exc:
        raise AgentError("Agent در دسترس نیست؛ کانفیگ در دیتابیس نگه داشته شد.") from exc
    if r.status_code == 404:
        return
    if r.status_code >= 300:
        try: detail = r.json().get("detail", "")
        except Exception: detail = r.text[:300]
        raise AgentError(f"حذف کاربر از Xray انجام نشد: {detail or r.status_code}")


def check_agent(node) -> dict:
    token = decrypt_secret(node.agent_token_encrypted)
    try:
        r = requests.get(_url(node, "/v1/status"),
                         headers={"Authorization": f"Bearer {token}"}, timeout=(5, 15))
    except requests.RequestException as exc:
        raise AgentError("اتصال به Agent برقرار نشد؛ آدرس HTTPS و وضعیت VPS را بررسی کن.") from exc
    if r.status_code >= 300:
        try: detail = r.json().get("detail", "")
        except Exception: detail = r.text[:300]
        raise AgentError(f"آزمایش اتصال ناموفق بود: {detail or r.status_code}")
    try:
        result = r.json()
    except ValueError as exc:
        raise AgentError("پاسخ Agent قابل خواندن نیست.") from exc
    if not result.get("ok"):
        raise AgentError("Agent پاسخ داد اما وضعیت را تأیید نکرد.")
    return result
