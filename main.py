from __future__ import annotations
import asyncio, html, ipaddress, json, os, secrets, shlex, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from database import SessionLocal, engine, get_db, init_db
from models import Admin, AuditLog, Client, Node, utcnow
from security import password_hash, verify_password, encrypt_secret, decrypt_secret, new_token, token_hash, csrf_token, constant_time_equal
from protocols import PROTOCOLS, TRANSPORTS, SECURITIES, SS_CIPHERS, ConfigError, build_config, build_inbound, format_bytes, safe_host
from agent_client import add_inbound, remove_inbound, check_agent, AgentError

ROOT = Path(__file__).resolve().parent
APP_NAME = os.getenv("APP_NAME", "RIX STORM PANEL 2.4")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
APP_ENV = os.getenv("APP_ENV", "development").lower()
SECRET_KEY = os.getenv("SECRET_KEY", "local-dev-change-this-secret-before-deploy-00000000000000000000000000000000")
SESSION_AGE = int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))
templates = Jinja2Templates(directory=str(ROOT))
_expiry_task: asyncio.Task | None = None

async def _expiry_sweeper() -> None:
    # Enforce date expiry and any manually recorded quota exhaustion. This is not live traffic metering.
    while True:
        await asyncio.sleep(60)
        with SessionLocal() as db:
            now = utcnow()
            due = db.scalars(select(Client).where(Client.enabled.is_(True),
                ((Client.expires_at.is_not(None) & (Client.expires_at <= now)) |
                 ((Client.quota_bytes > 0) & (Client.used_bytes >= Client.quota_bytes))))).all()
            for client in due:
                node = db.get(Node, client.node_id)
                if not node:
                    continue
                try:
                    remove_inbound(node, client.inbound_tag)
                    client.enabled = False
                    client.updated_at = utcnow()
                    db.add(AuditLog(admin_id=None, action="client.auto_disable", entity="client",
                                    entity_id=str(client.id), details="expiry/quota threshold reached"))
                    db.commit()
                except Exception:
                    db.rollback()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _expiry_task
    if APP_ENV == "production":
        if len(SECRET_KEY) < 40 or SECRET_KEY.startswith("local-dev"):
            raise RuntimeError("برای production یک SECRET_KEY تصادفی حداقل ۴۰ کاراکتری تنظیم کن.")
        if not os.getenv("DATA_ENCRYPTION_KEY"):
            raise RuntimeError("متغیر DATA_ENCRYPTION_KEY در Railway الزامی است.")
        if not os.getenv("ADMIN_USERNAME") or len(os.getenv("ADMIN_PASSWORD", "")) < 16:
            raise RuntimeError("ADMIN_USERNAME و ADMIN_PASSWORD حداقل ۱۶ کاراکتری را تنظیم کن.")
    init_db()
    username, password = os.getenv("ADMIN_USERNAME", "").strip(), os.getenv("ADMIN_PASSWORD", "")
    if username and password:
        with SessionLocal() as db:
            if not db.scalar(select(Admin).where(Admin.username == username)):
                db.add(Admin(username=username, password_hash=password_hash(password), active=True))
                db.commit()
    _expiry_task = asyncio.create_task(_expiry_sweeper())
    try:
        yield
    finally:
        if _expiry_task and not _expiry_task.done():
            _expiry_task.cancel()
            try:
                await _expiry_task
            except asyncio.CancelledError:
                pass
        _expiry_task = None


app = FastAPI(title=APP_NAME, docs_url=None if APP_ENV == "production" else "/docs", redoc_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="rix_storm_session", max_age=SESSION_AGE,
                   same_site="lax", https_only=APP_ENV == "production")

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.url.path.startswith(("/s/", "/sub/")):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

@app.exception_handler(StarletteHTTPException)
async def friendly_http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code in (303, 307, 308) and exc.headers and exc.headers.get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=exc.status_code)
    if request.url.path.startswith(("/s/", "/sub/")) and exc.status_code in (403, 404, 410):
        safe_detail = html.escape(str(exc.detail))
        return HTMLResponse(f"<!doctype html><html lang='fa' dir='rtl'><meta charset='utf-8'><title>اشتراک در دسترس نیست</title><body style='font:16px sans-serif;max-width:620px;margin:10vh auto;padding:24px;background:#111820;color:#edf3f7;border-radius:20px'><h2>این اشتراک در دسترس نیست</h2><p>{safe_detail}</p><a style='color:#85dfb5' href='/'>بازگشت به پنل</a></body></html>", status_code=exc.status_code, headers={"Cache-Control": "no-store"})
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers or {})

@app.get("/health", include_in_schema=False)
def health():
    """Lightweight platform health probe; does not reveal secrets or server details."""
    return {"ok": True, "service": "rix-storm-panel", "version": "2.4"}



@app.get("/install-node.sh", include_in_schema=False)
def install_node_script():
    """Serve the generic installer; credentials are supplied by the admin's generated command."""
    path = ROOT / "install_xray_agent.sh"
    if not path.is_file():
        raise HTTPException(404, "Installer is not packaged with this panel version.")
    return FileResponse(path, media_type="text/x-shellscript", filename="install-node.sh",
                        headers={"Cache-Control": "no-store"})

@app.get("/xray-agent.py", include_in_schema=False)
def xray_agent_source():
    """Allow the installer on the VPS to fetch the exact Agent version shipped with the panel."""
    path = ROOT / "xray_agent.py"
    if not path.is_file():
        raise HTTPException(404, "Xray Agent source is not packaged with this panel version.")
    return FileResponse(path, media_type="text/x-python", filename="xray_agent.py",
                        headers={"Cache-Control": "no-store"})

@app.get("/app.css", include_in_schema=False)
def css():
    return FileResponse(ROOT / "app.css", media_type="text/css", headers={"Cache-Control": "public, max-age=300"})

@app.get("/app.js", include_in_schema=False)
def javascript():
    return FileResponse(ROOT / "app.js", media_type="application/javascript", headers={"Cache-Control": "public, max-age=300"})

def _base_url(request: Request) -> str:
    return PUBLIC_BASE_URL or str(request.base_url).rstrip("/")

def _flash(request: Request, message: str, kind: str = "success") -> None:
    request.session["flash"] = {"message": message, "kind": kind}

def _render(request: Request, template: str, **ctx: Any) -> HTMLResponse:
    flash = request.session.pop("flash", None)
    context = {"request": request, "app_name": APP_NAME, "csrf": csrf_token(request.session), "flash": flash,
               "admin": None, "nav": "", "page_title": APP_NAME, "protocols": PROTOCOLS,
               "transports": sorted(TRANSPORTS), "securities": sorted(SECURITIES), "ciphers": sorted(SS_CIPHERS),
               "base_url": _base_url(request)}
    context.update(ctx)
    return templates.TemplateResponse(request=request, name=template, context=context)

async def _form(request: Request) -> dict[str, str]:
    form = await request.form()
    return {str(k): str(v) for k, v in form.items()}

async def _verify_csrf(request: Request) -> dict[str, str]:
    data = await _form(request)
    sent, expected = data.get("csrf", ""), request.session.get("_csrf", "")
    if not sent or not expected or not constant_time_equal(sent, expected):
        raise HTTPException(status_code=403, detail="درخواست نامعتبر یا منقضی شده است؛ صفحه را تازه‌سازی کن.")
    return data

def _admin(request: Request, db: Session) -> Admin:
    admin_id = request.session.get("admin_id")
    if not admin_id:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    admin = db.get(Admin, int(admin_id))
    if not admin or not admin.active:
        request.session.clear()
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return admin

def _audit(db: Session, admin: Admin | None, action: str, entity: str, entity_id: object | None, details: str = "") -> None:
    db.add(AuditLog(admin_id=admin.id if admin else None, action=action, entity=entity,
                    entity_id=str(entity_id) if entity_id is not None else None, details=details[:500]))

def _required(data: dict[str, str], key: str, label: str, max_len: int = 255) -> str:
    value = data.get(key, "").strip()
    if not value: raise ValueError(f"{label} الزامی است.")
    if len(value) > max_len: raise ValueError(f"{label} بیش از حد طولانی است.")
    return value

def _int_range(value: str, label: str, low: int, high: int) -> int:
    try: number = int(value)
    except (ValueError, TypeError) as exc: raise ValueError(f"{label} باید عدد صحیح باشد.") from exc
    if not low <= number <= high: raise ValueError(f"{label} باید بین {low} و {high} باشد.")
    return number

def _gib_to_bytes(value: str, label: str) -> int:
    try: amount = float(value or "0")
    except ValueError as exc: raise ValueError(f"{label} باید عددی باشد.") from exc
    if amount < 0 or amount > 1_000_000: raise ValueError(f"{label} خارج از محدوده مجاز است.")
    return int(amount * (1024 ** 3))

def _node_from_form(data: dict[str, str], node: Node | None = None) -> Node:
    """Build a node with sensible defaults so the normal setup has only 3 fields."""
    name = _required(data, "name", "نام سرور", 120)
    host = safe_host(_required(data, "host", "دامنه سرور", 255))
    if node is None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith((".local", ".internal", ".test")):
                raise ValueError("برای نصب خودکار یک دامنهٔ عمومی واقعی وارد کن که به IP این VPS اشاره کند.")
        else:
            raise ValueError("برای نصب خودکار و دریافت گواهی HTTPS، دامنهٔ عمومی وارد کن که به IP این VPS اشاره کند؛ IP را در فیلد Proxy IP قرار بده.")
    proxy_ip = data.get("proxy_ip", "").strip() or None
    if proxy_ip:
        proxy_ip = safe_host(proxy_ip)

    # The standard setup uses a public DNS name for the HTTPS Agent and TLS.
    # IP-only hosts are still accepted for legacy/manual nodes, but the UI explains
    # that the one-command installer needs a domain with DNS pointing to this VPS.
    start = _int_range(data.get("port_start", str(node.port_start if node else 20000)), "ابتدای بازه پورت", 1024, 65535)
    end = _int_range(data.get("port_end", str(node.port_end if node else 20100)), "انتهای بازه پورت", 1024, 65535)
    if end < start or end - start > 10000:
        raise ValueError("بازه پورت نامعتبر است؛ فاصله ابتدا و انتها حداکثر ۱۰۰۰۰ باشد.")

    agent_url = data.get("agent_url", "").strip().rstrip("/") or ((node.agent_url if node and host == node.host else f"https://{host}") if node else f"https://{host}")
    if not agent_url.startswith("https://"):
        raise ValueError("آدرس Agent باید با https:// شروع شود.")
    token = data.get("agent_token", "").strip()
    if node is None and not token:
        token = new_token(48)
    if node is None and len(token) < 32:
        raise ValueError("توکن Agent باید حداقل ۳۲ کاراکتر تصادفی داشته باشد.")
    if token and len(token) < 32:
        raise ValueError("توکن Agent باید حداقل ۳۲ کاراکتر باشد.")

    tls_sni = data.get("tls_sni", "").strip() or (host if node is None else node.tls_sni) or host
    if tls_sni:
        tls_sni = safe_host(tls_sni)
    cert_path = data.get("tls_cert_path", "").strip() or (node.tls_cert_path if node else "/etc/rix-storm/tls/fullchain.pem")
    key_path = data.get("tls_key_path", "").strip() or (node.tls_key_path if node else "/etc/rix-storm/tls/privkey.pem")
    if bool(cert_path) != bool(key_path):
        raise ValueError("مسیر گواهی TLS و کلید TLS باید هر دو وارد شوند.")
    reality_sni = data.get("reality_sni", "").strip() or (node.reality_sni if node else None) or "www.microsoft.com"
    if reality_sni:
        reality_sni = safe_host(reality_sni)
    reality_public_key = data.get("reality_public_key", "").strip() or (node.reality_public_key if node else None) or None
    reality_short_id = data.get("reality_short_id", "").strip() or (node.reality_short_id if node else None) or None
    if reality_short_id and not __import__("re").fullmatch(r"[0-9a-fA-F]{1,16}", reality_short_id):
        raise ValueError("Reality Short ID باید ۱ تا ۱۶ رقم هگزادسیمال باشد.")
    reality_private_key = data.get("reality_private_key", "").strip()

    if node is None:
        node = Node(name=name, host=host, proxy_ip=proxy_ip, port_start=start, port_end=end,
                    agent_url=agent_url, agent_token_encrypted=encrypt_secret(token), tls_sni=tls_sni,
                    tls_cert_path=cert_path, tls_key_path=key_path, reality_sni=reality_sni,
                    reality_public_key=reality_public_key, reality_short_id=reality_short_id,
                    enabled=data.get("enabled", "true").lower() in {"1", "true", "yes", "on"},
                    notes=data.get("notes", "").strip()[:1000] or None)
    else:
        node.name, node.host, node.proxy_ip = name, host, proxy_ip
        node.port_start, node.port_end, node.agent_url = start, end, agent_url
        if token:
            node.agent_token_encrypted = encrypt_secret(token)
        node.tls_sni, node.tls_cert_path, node.tls_key_path = tls_sni, cert_path, key_path
        node.reality_sni = reality_sni
        if reality_public_key:
            node.reality_public_key = reality_public_key
        if reality_short_id:
            node.reality_short_id = reality_short_id
        node.enabled = data.get("enabled", "false").lower() in {"1", "true", "yes", "on"}
        node.notes = data.get("notes", "").strip()[:1000] or None
    if reality_private_key:
        node.reality_private_key_encrypted = encrypt_secret(reality_private_key)
    return node

def _next_port(db: Session, node: Node) -> int:
    used = set(db.scalars(select(Client.port).where(Client.node_id == node.id)).all())
    for port in range(node.port_start, node.port_end + 1):
        if port not in used: return port
    raise ValueError("تمام پورت‌های این نود مصرف شده‌اند؛ بازه پورت را بزرگ‌تر کن.")

def _client_status(client: Client) -> tuple[str, str]:
    if not client.enabled: return "غیرفعال", "muted"
    if client.expires_at and client.expires_at <= utcnow(): return "منقضی‌شده", "danger"
    if client.quota_bytes and client.used_bytes >= client.quota_bytes: return "حجم تمام‌شده", "danger"
    return "فعال", "success"

def _share_url(request: Request, client: Client) -> str:
    return f"{_base_url(request)}/s/{decrypt_secret(client.subscription_token_encrypted)}"

def _client_state(client: Client, node: Node) -> dict[str, Any]:
    status, kind = _client_status(client)
    remaining = max(0, client.quota_bytes - client.used_bytes) if client.quota_bytes else None
    usage = min(100, round(client.used_bytes / client.quota_bytes * 100)) if client.quota_bytes else 0
    days_left = max(0, int((client.expires_at - utcnow()).total_seconds() // 86400)) if client.expires_at else None
    config = decrypt_secret(client.config_encrypted)
    return {"status": status, "status_kind": kind, "config_text": config,
            "remaining_bytes": remaining, "usage_percent": usage, "days_left": days_left,
            "quota_text": "نامحدود" if not client.quota_bytes else format_bytes(client.quota_bytes),
            "used_text": format_bytes(client.used_bytes),
            "remaining_text": "نامحدود" if remaining is None else format_bytes(remaining),
            "expires_text": client.expires_at.strftime("%Y/%m/%d") if client.expires_at else "بدون انقضا",
            "node_endpoint": f"{node.proxy_ip or node.host}:{client.port}"}

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    admin = _admin(request, db)
    total_clients = db.scalar(select(func.count(Client.id))) or 0
    current = utcnow()
    active = db.scalar(select(func.count(Client.id)).where(Client.enabled.is_(True),
        ((Client.expires_at.is_(None)) | (Client.expires_at > current)),
        ((Client.quota_bytes == 0) | (Client.used_bytes < Client.quota_bytes)))) or 0
    node_count = db.scalar(select(func.count(Node.id))) or 0
    used = db.scalar(select(func.sum(Client.used_bytes))) or 0
    clients = db.scalars(select(Client).order_by(desc(Client.created_at)).limit(7)).all()
    nodes = db.scalars(select(Node).order_by(desc(Node.created_at)).limit(4)).all()
    rows = []
    for client in clients:
        node = db.get(Node, client.node_id)
        status, kind = _client_status(client)
        rows.append({"client": client, "node": node, "status": status, "status_kind": kind,
                     "share_url": _share_url(request, client)})
    return _render(request, "dashboard.html", admin=admin, nav="dashboard", page_title="نمای کلی",
                   client_count=total_clients, active_count=active, node_count=node_count,
                   used_text=format_bytes(used), clients=rows, nodes=nodes)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("admin_id"): return RedirectResponse("/", status_code=303)
    return _render(request, "login.html", hide_shell=True, page_title="ورود مدیر")

@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await _verify_csrf(request)
    username, password = data.get("username", "").strip(), data.get("password", "")
    admin = db.scalar(select(Admin).where(Admin.username == username))
    if not admin or not admin.active or not verify_password(password, admin.password_hash):
        _flash(request, "نام کاربری یا رمز عبور صحیح نیست.", "error")
        return RedirectResponse("/login", status_code=303)
    request.session.clear()
    request.session["admin_id"] = admin.id
    csrf_token(request.session)
    _audit(db, admin, "auth.login", "admin", admin.id, "ورود موفق")
    db.commit()
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await _verify_csrf(request)
    admin_id = request.session.get("admin_id")
    admin = db.get(Admin, int(admin_id)) if admin_id else None
    if admin: _audit(db, admin, "auth.logout", "admin", admin.id)
    db.commit(); request.session.clear()
    return RedirectResponse("/login", status_code=303)

@app.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request, db: Session = Depends(get_db)):
    admin = _admin(request, db)
    nodes = db.scalars(select(Node).order_by(desc(Node.created_at))).all()
    counts = {n.id: db.scalar(select(func.count(Client.id)).where(Client.node_id == n.id)) or 0 for n in nodes}
    panel_url = _base_url(request)
    setup_commands: dict[int, str] = {}
    setup_notes: dict[int, str] = {}
    for node in nodes:
        try:
            ipaddress.ip_address(node.host)
            setup_notes[node.id] = "نصب خودکار HTTPS به دامنهٔ واقعی نیاز دارد؛ یک دامنه را به IP این VPS متصل کن و آن را به‌عنوان دامنه سرور وارد کن."
        except ValueError:
            token = decrypt_secret(node.agent_token_encrypted)
            command = (f"set -o pipefail; curl -fsSL {shlex.quote(panel_url + '/install-node.sh')} | bash -s -- "
                       f"--domain {shlex.quote(node.host)} --agent-token {shlex.quote(token)} "
                       f"--panel-url {shlex.quote(panel_url)} --port-start {node.port_start} --port-end {node.port_end}")
            setup_commands[node.id] = command
            setup_notes[node.id] = "قبل از اجرا: دامنه باید به IP همین VPS اشاره کند؛ سرور Debian/Ubuntu بهتر است تازه باشد و پورت‌های 80، 443 و بازهٔ کانفیگ آزاد باشند."
    return _render(request, "nodes.html", admin=admin, nav="nodes", page_title="سرورها", nodes=nodes,
                   counts=counts, setup_commands=setup_commands, setup_notes=setup_notes)

@app.post("/nodes/create")
async def node_create(request: Request, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db)
    try:
        node = _node_from_form(data)
        db.add(node); db.flush()
        _audit(db, admin, "node.create", "node", node.id, f"host={node.host}; range={node.port_start}-{node.port_end}")
        db.commit(); _flash(request, "سرور ذخیره شد. دستور نصب خودکار را از کارت سرور کپی کن و روی VPS اجرا کن؛ سپس «آزمایش اتصال» را بزن.")
    except (ValueError, RuntimeError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/nodes", status_code=303)

@app.post("/nodes/{node_id}/update")
async def node_update(request: Request, node_id: int, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db); node = db.get(Node, node_id)
    if not node: _flash(request, "سرور پیدا نشد.", "error"); return RedirectResponse("/nodes", status_code=303)
    try:
        _node_from_form(data, node); node.updated_at = utcnow()
        _audit(db, admin, "node.update", "node", node.id, f"host={node.host}")
        db.commit(); _flash(request, "تنظیمات سرور ذخیره شد.")
    except (ValueError, RuntimeError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/nodes", status_code=303)

@app.post("/nodes/{node_id}/test")
async def node_test(request: Request, node_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db); node = db.get(Node, node_id)
    if not node:
        _flash(request, "سرور پیدا نشد.", "error")
    else:
        try:
            status = check_agent(node)
            total = int(status.get("managed_inbounds", 0))
            active = int(status.get("active_managed_inbounds", 0))
            # Auto-import TLS and Reality material created by the installer; no manual key copying.
            tls_cert_path = str(status.get("tls_cert_path", "")).strip()
            tls_key_path = str(status.get("tls_key_path", "")).strip()
            if tls_cert_path and tls_key_path:
                node.tls_cert_path, node.tls_key_path = tls_cert_path, tls_key_path
            node_domain = str(status.get("node_domain", "")).strip()
            if node_domain:
                try: node.tls_sni = safe_host(node_domain)
                except ValueError: pass
            reality_private_key = str(status.get("reality_private_key", "")).strip()
            reality_public_key = str(status.get("reality_public_key", "")).strip()
            reality_short_id = str(status.get("reality_short_id", "")).strip()
            reality_sni = str(status.get("reality_sni", "")).strip()
            if reality_private_key and reality_public_key and reality_short_id:
                node.reality_private_key_encrypted = encrypt_secret(reality_private_key)
                node.reality_public_key = reality_public_key
                node.reality_short_id = reality_short_id
            if reality_sni:
                try: node.reality_sni = safe_host(reality_sni)
                except ValueError: pass
            node.updated_at = utcnow()
            auto_configured = bool(reality_private_key and reality_public_key and reality_short_id and tls_cert_path and tls_key_path)
            _audit(db, admin, "node.test", "node", node.id, f"active={active}; managed={total}; auto_configured={auto_configured}")
            db.commit()
            message = f"اتصال Agent و Xray موفق بود؛ {active} از {total} ورودی مدیریت‌شده فعال است."
            message += " تنظیمات TLS و Reality خودکار همگام شد." if auto_configured else " Agent وصل است، اما اطلاعات نصب خودکار TLS/Reality برنگشت؛ نسخهٔ Agent و نصب‌کننده را بررسی کن."
            _flash(request, message)
        except AgentError as exc:
            _flash(request, str(exc), "error")
    return RedirectResponse("/nodes", status_code=303)


@app.post("/nodes/{node_id}/delete")
async def node_delete(request: Request, node_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db); node = db.get(Node, node_id)
    if not node: _flash(request, "سرور پیدا نشد.", "error")
    elif db.scalar(select(func.count(Client.id)).where(Client.node_id == node.id)):
        _flash(request, "این سرور هنوز کاربر دارد؛ کاربران را حذف یا منتقل کن.", "error")
    else:
        _audit(db, admin, "node.delete", "node", node.id, node.name)
        db.delete(node); db.commit(); _flash(request, "سرور حذف شد.")
    return RedirectResponse("/nodes", status_code=303)

@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, db: Session = Depends(get_db)):
    admin = _admin(request, db)
    clients = db.scalars(select(Client).order_by(desc(Client.created_at))).all()
    nodes = db.scalars(select(Node).where(Node.enabled.is_(True)).order_by(Node.name)).all()
    rows = []
    for client in clients:
        node = db.get(Node, client.node_id)
        status, kind = _client_status(client)
        rows.append({"client": client, "node": node, "status": status, "status_kind": kind,
                     "share_url": _share_url(request, client), "config": decrypt_secret(client.config_encrypted)})
    return _render(request, "clients.html", admin=admin, nav="clients", page_title="کاربران و اشتراک‌ها", clients=rows, nodes=nodes)

@app.post("/clients/create")
async def client_create(request: Request, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db)
    node = None
    inbound = None
    try:
        name = _required(data, "name", "نام کاربر", 120)
        protocol = data.get("protocol", "vless").strip().lower()
        if protocol not in PROTOCOLS: raise ValueError("پروتکل پشتیبانی نمی‌شود.")
        raw_node_id = data.get("node_id", "").strip()
        if raw_node_id:
            try: node_id = int(raw_node_id)
            except ValueError as exc: raise ValueError("سرور انتخاب‌شده معتبر نیست.") from exc
            node = db.get(Node, node_id)
        else:
            available_nodes = db.scalars(select(Node).where(Node.enabled.is_(True)).order_by(Node.name)).all()
            node = available_nodes[0] if len(available_nodes) == 1 else None
        if not node or not node.enabled:
            raise ValueError("برای ساخت اتصال واقعی، ابتدا یک سرور فعال را در بخش «سرورها» یک‌بار تنظیم کن؛ بعد از آن اگر فقط یک سرور داشته باشی، انتخاب آن خودکار است.")
        transport = data.get("transport", "tcp").strip().lower() or "tcp"
        security = data.get("security", "auto").strip().lower() or "auto"
        if security == "auto":
            if protocol == "shadowsocks":
                security = "none"
            elif protocol == "trojan":
                security = "tls"
            elif (protocol == "vless" and transport == "tcp" and node.reality_public_key and node.reality_short_id
                  and node.reality_private_key_encrypted):
                security = "reality"
            elif node.tls_cert_path and node.tls_key_path:
                security = "tls"
            else:
                security = "none"
        if transport not in TRANSPORTS: raise ValueError("روش انتقال معتبر نیست.")
        if security not in SECURITIES: raise ValueError("روش امنیتی معتبر نیست.")
        if protocol == "shadowsocks":
            transport, security = "tcp", "none"
        if protocol == "trojan": security = "tls"
        if security == "reality" and protocol != "vless": raise ValueError("Reality فقط برای VLESS در دسترس است.")
        if transport == "xhttp" and protocol != "vless": raise ValueError("XHTTP فقط برای VLESS فعال است.")
        if security == "reality" and transport == "ws": raise ValueError("Reality و WebSocket را هم‌زمان انتخاب نکن.")
        sni = data.get("sni", "").strip()
        if security == "tls": sni = safe_host(sni or node.tls_sni or node.host)
        elif security == "reality": sni = safe_host(sni or node.reality_sni or "")
        else: sni = safe_host(sni or node.host)
        if protocol in {"vless", "vmess"}: credential = str(uuid.uuid4())
        else: credential = secrets.token_urlsafe(24)
        email = f"rix-{secrets.token_hex(8)}@rix.local"
        tag = f"rix-{secrets.token_hex(12)}"
        port = _next_port(db, node)
        quota_bytes = _gib_to_bytes(data.get("quota_gb", "0"), "سهمیه (GB)")
        try: days = int(data.get("duration_days", "0") or "0")
        except ValueError as exc: raise ValueError("مدت اعتبار باید عدد صحیح باشد.") from exc
        if not 0 <= days <= 3650: raise ValueError("مدت اعتبار باید بین صفر تا ۳۶۵۰ روز باشد.")
        expires_at = utcnow() + timedelta(days=days) if days else None
        user_options = {"protocol": protocol, "transport": transport, "security": security,
                        "sni": sni, "path": data.get("path", "/").strip() or "/",
                        "service_name": data.get("service_name", "grpc-service").strip() or "grpc-service",
                        "flow": data.get("flow", "").strip(),
                        "cipher": data.get("cipher", "chacha20-ietf-poly1305").strip()}
        if user_options["flow"] and (protocol != "vless" or security != "reality" or transport != "tcp"):
            raise ValueError("Flow فقط برای VLESS + Reality + TCP مجاز است.")
        if user_options["cipher"] not in SS_CIPHERS: raise ValueError("Cipher برای Shadowsocks معتبر نیست.")
        inbound = build_inbound(node, user_options, credential, email, port, tag)
        config = build_config(node, protocol, transport, security, credential, port, name, sni,
                              user_options["path"], user_options["service_name"], user_options["flow"], user_options["cipher"])
        # Provision on Xray first. A DB record is only created after the Agent confirms success.
        add_inbound(node, inbound)
        sub_token = new_token(32)
        client = Client(name=name, protocol=protocol, transport=transport, security=security, node_id=node.id,
                        port=port, inbound_tag=tag, email=email, credential_encrypted=encrypt_secret(credential),
                        inbound_json_encrypted=encrypt_secret(json.dumps(inbound, separators=(",", ":"))),
                        config_encrypted=encrypt_secret(config), subscription_token_hash=token_hash(sub_token),
                        subscription_token_encrypted=encrypt_secret(sub_token), quota_bytes=quota_bytes,
                        used_bytes=0, expires_at=expires_at, enabled=True,
                        note=data.get("note", "").strip()[:1000] or None)
        try:
            db.add(client); db.flush()
            _audit(db, admin, "client.create", "client", client.id,
                   f"protocol={protocol}; transport={transport}; security={security}; port={port}")
            db.commit()
        except Exception:
            db.rollback()
            try: remove_inbound(node, tag)
            except Exception: pass
            raise
        _flash(request, f"کاربر ساخته شد و روی Xray ثبت شد؛ پورت اتصال: {port}.")
    except (ValueError, RuntimeError, ConfigError, AgentError, HTTPException) as exc:
        db.rollback()
        detail = getattr(exc, "detail", str(exc))
        _flash(request, str(detail), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/toggle")
async def client_toggle(request: Request, client_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db); client = db.get(Client, client_id)
    if not client: _flash(request, "کاربر پیدا نشد.", "error"); return RedirectResponse("/clients", status_code=303)
    node = db.get(Node, client.node_id)
    try:
        if client.enabled:
            remove_inbound(node, client.inbound_tag)
            client.enabled = False
            _flash(request, "کاربر در Xray غیرفعال شد.")
        else:
            if client.expires_at and client.expires_at <= utcnow(): raise ValueError("اعتبار کاربر تمام شده است؛ تاریخ انقضا را اصلاح یا کاربر تازه بساز.")
            if client.quota_bytes and client.used_bytes >= client.quota_bytes: raise ValueError("حجم کاربر تمام شده است.")
            inbound = json.loads(decrypt_secret(client.inbound_json_encrypted))
            add_inbound(node, inbound)
            client.enabled = True
            _flash(request, "کاربر دوباره در Xray فعال شد.")
        client.updated_at = utcnow()
        _audit(db, admin, "client.toggle", "client", client.id, f"enabled={client.enabled}")
        db.commit()
    except (AgentError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/delete")
async def client_delete(request: Request, client_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db); client = db.get(Client, client_id)
    if not client: _flash(request, "کاربر پیدا نشد.", "error"); return RedirectResponse("/clients", status_code=303)
    node = db.get(Node, client.node_id)
    try:
        remove_inbound(node, client.inbound_tag)
        _audit(db, admin, "client.delete", "client", client.id, f"name={client.name}; tag={client.inbound_tag}")
        db.delete(client); db.commit(); _flash(request, "کاربر از Xray حذف شد.")
    except (AgentError, RuntimeError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/usage")
async def client_usage(request: Request, client_id: int, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db); client = db.get(Client, client_id)
    if not client: _flash(request, "کاربر پیدا نشد.", "error"); return RedirectResponse("/clients", status_code=303)
    try:
        client.used_bytes = _gib_to_bytes(data.get("used_gb", "0"), "مصرف ثبت‌شده (GB)")
        if client.quota_bytes and client.used_bytes > client.quota_bytes: raise ValueError("مصرف نمی‌تواند از سهمیه بیشتر باشد.")
        if client.enabled and client.quota_bytes and client.used_bytes >= client.quota_bytes:
            node = db.get(Node, client.node_id)
            remove_inbound(node, client.inbound_tag)
            client.enabled = False
        _audit(db, admin, "client.usage.update", "client", client.id, f"used_bytes={client.used_bytes}; enabled={client.enabled}")
        db.commit(); _flash(request, "مصرف ثبت‌شده ذخیره شد. توجه: این مقدار دستی است و هنوز آمار زنده Xray نیست.", "info")
    except ValueError as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.get("/s/{token}", response_class=HTMLResponse)
def public_subscription(request: Request, token: str, db: Session = Depends(get_db)):
    client = db.scalar(select(Client).where(Client.subscription_token_hash == token_hash(token)))
    if not client: raise HTTPException(status_code=404, detail="لینک اشتراک نامعتبر یا باطل شده است.")
    node = db.get(Node, client.node_id)
    if not node: raise HTTPException(status_code=404, detail="سرور این اشتراک دیگر در دسترس نیست.")
    state = _client_state(client, node)
    return _render(request, "subscription.html", hide_shell=True, public=True, client=client, node=node, state=state,
                   page_title="ساب‌پنل اشتراک", token=token, subscription_url=f"{_base_url(request)}/s/{token}",
                   raw_url=f"{_base_url(request)}/sub/{token}.txt", qr_url=f"/s/{token}/qr.png", download_url=f"/s/{token}/download")

def _public_config(token: str, db: Session) -> tuple[Client, Node, str]:
    client = db.scalar(select(Client).where(Client.subscription_token_hash == token_hash(token)))
    if not client: raise HTTPException(status_code=404, detail="لینک اشتراک نامعتبر یا باطل شده است.")
    node = db.get(Node, client.node_id)
    if not node: raise HTTPException(status_code=404, detail="سرور این اشتراک وجود ندارد.")
    status, _ = _client_status(client)
    if not client.enabled or status in {"منقضی‌شده", "حجم تمام‌شده"}:
        raise HTTPException(status_code=410, detail="اشتراک غیرفعال، منقضی یا تمام‌شده است.")
    return client, node, decrypt_secret(client.config_encrypted)

@app.get("/sub/{token}.txt")
def raw_subscription(token: str, db: Session = Depends(get_db)):
    client, _node, config = _public_config(token, db)
    return PlainTextResponse(config + "\n", media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"inline; filename=rix-{client.id}-subscription.txt", "Cache-Control": "no-store"})

@app.get("/s/{token}/download")
def download_subscription(token: str, db: Session = Depends(get_db)):
    client, _node, config = _public_config(token, db)
    suffix = ".conf" if client.protocol == "wireguard" else ".txt"
    return Response(config + ("" if config.endswith("\n") else "\n"), media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="rix-{client.id}-{client.protocol}{suffix}"', "Cache-Control": "no-store"})

@app.get("/s/{token}/qr.png")
def qr_code(token: str, db: Session = Depends(get_db)):
    _client, _node, config = _public_config(token, db)
    import io
    image = qrcode.make(config)
    output = io.BytesIO(); image.save(output, format="PNG")
    return Response(output.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})
