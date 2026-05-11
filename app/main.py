import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "mvp.db"
APP_ENV = os.getenv("APP_ENV", "dev")
TOKEN_TTL_DAYS = int(os.getenv("TOKEN_TTL_DAYS", "30"))
BILLING_WEBHOOK_SECRET = os.getenv("BILLING_WEBHOOK_SECRET", "dev-webhook-secret")

PLAN_LIMITS = {"free": 2, "basic": 50, "pro": 300}
RATE_LIMIT_PER_MINUTE = 30
GEN_RATE_BUCKET: dict[str, deque] = defaultdict(deque)

PERMISSIONS = {
    "view_users",
    "manage_orders",
    "configure_templates",
    "view_metrics",
}

app = FastAPI(title="AI Short-video Script Generator")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


class RegisterInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class GenerateInput(BaseModel):
    industry: str = Field(pattern="^(restaurant|beauty)$")
    business_name: str = Field(min_length=1, max_length=80)
    main_offer: str = Field(min_length=1, max_length=120)
    avg_ticket: str = Field(min_length=1, max_length=40)
    audience: str = Field(min_length=1, max_length=80)
    goal: str = Field(min_length=1, max_length=40)


class UpgradeInput(BaseModel):
    user_id: int
    plan: str = Field(pattern="^(free|basic|pro)$")


class RegenerateItemInput(GenerateInput):
    index: int = Field(ge=0, le=9)


class BillingWebhookInput(BaseModel):
    order_id: int
    status: str = Field(pattern="^(paid|failed)$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(raw: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{raw}".encode("utf-8")).hexdigest()


def create_password_fields(raw: str) -> tuple[str, str]:
    salt = secrets.token_hex(8)
    return salt, hash_password(raw, salt)


def verify_password(raw: str, salt: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_password(raw, salt), hashed)


def assert_secure_config() -> None:
    if APP_ENV == "prod":
        return


def check_rate_limit(key: str) -> None:
    now = utcnow()
    bucket = GEN_RATE_BUCKET[key]
    while bucket and (now - bucket[0]).total_seconds() > 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                permissions_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                organization_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(organization_id) REFERENCES organizations(id)
            );

            CREATE TABLE IF NOT EXISTS memberships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                UNIQUE(user_id, organization_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(organization_id) REFERENCES organizations(id),
                FOREIGN KEY(role_id) REFERENCES roles(id)
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS generations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(organization_id) REFERENCES organizations(id)
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                plan TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                paid_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(organization_id) REFERENCES organizations(id)
            );
            """
        )
        seed_roles(conn)


def seed_roles(conn: sqlite3.Connection) -> None:
    default_roles = {
        "owner": sorted(PERMISSIONS),
        "analyst": ["view_metrics"],
        "ops": ["manage_orders"],
        "viewer": ["view_users"],
    }
    for name, perms in default_roles.items():
        conn.execute(
            "INSERT OR IGNORE INTO roles(name, permissions_json) VALUES (?, ?)",
            (name, json.dumps(perms)),
        )


@app.on_event("startup")
def on_startup() -> None:
    assert_secure_config()
    init_db()


def get_current_user(authorization: str | None) -> sqlite3.Row:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.replace("Bearer ", "", 1).strip()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.* FROM users u
            JOIN tokens t ON t.user_id = u.id
            WHERE t.token = ? AND t.revoked = 0 AND t.expires_at > ?
            """,
            (token, utcnow().isoformat()),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return row


def get_user_permissions(user_id: int, organization_id: int) -> set[str]:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT r.permissions_json FROM memberships m
            JOIN roles r ON r.id = m.role_id
            WHERE m.user_id = ? AND m.organization_id = ?
            """,
            (user_id, organization_id),
        ).fetchone()
    if not row:
        return set()
    return set(json.loads(row["permissions_json"]))


def require_permission(user: sqlite3.Row, permission: str) -> None:
    perms = get_user_permissions(user["id"], user["organization_id"])
    if permission not in perms:
        raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")


def monthly_usage(user_id: int, org_id: int) -> int:
    first_day = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as c FROM generations WHERE user_id = ? AND organization_id = ? AND created_at >= ?", (user_id, org_id, first_day)).fetchone()
    return int(row["c"])


def build_script(data: GenerateInput, idx: int) -> dict[str, Any]:
    hooks = {"restaurant": ["附近吃什么？", "这家店被低估了", "人均不高但很稳"], "beauty": ["做完变化太明显了", "学生党也能做", "本周预约快满了"]}
    hook = hooks[data.industry][idx % 3]
    return {"title": f"{data.business_name}选题{idx + 1}: {hook}", "hook_3s": f"{hook}，今天带你看{data.main_offer}", "voiceover": f"这里是{data.business_name}，主打{data.main_offer}，适合{data.audience}，人均约{data.avg_ticket}。本期目标：{data.goal}。", "shots": ["门头环境", "过程特写", "结果反馈"], "duration_sec": 20 + (idx % 3) * 5, "cta": "评论区回复关键词，领取到店福利"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html", context={"token_ttl_days": TOKEN_TTL_DAYS})


@app.post("/auth/register")
def register(data: RegisterInput) -> JSONResponse:
    now = utcnow().isoformat()
    salt, pwd_hash = create_password_fields(data.password)
    org_name = f"{data.email.split('@')[0]}-org"
    with get_conn() as conn:
        try:
            org_id = conn.execute("INSERT INTO organizations(name, created_at) VALUES (?, ?)", (org_name, now)).lastrowid
            cur = conn.execute("INSERT INTO users(email, password_salt, password_hash, organization_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (data.email, salt, pwd_hash, org_id, now, now))
            role_id = conn.execute("SELECT id FROM roles WHERE name = 'owner'").fetchone()["id"]
            conn.execute("INSERT INTO memberships(user_id, organization_id, role_id) VALUES (?, ?, ?)", (cur.lastrowid, org_id, role_id))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Email already exists")
    return JSONResponse({"user_id": cur.lastrowid, "plan": "free", "organization_id": org_id})

@app.post("/auth/login")
def login(data: LoginInput) -> JSONResponse:
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
        if not user or not verify_password(data.password, user["password_salt"], user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = secrets.token_urlsafe(24)
        now = utcnow(); expires_at = now + timedelta(days=TOKEN_TTL_DAYS)
        conn.execute("INSERT INTO tokens(token, user_id, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)", (token, user["id"], now.isoformat(), expires_at.isoformat()))
    return JSONResponse({"token": token, "token_expires_at": expires_at.isoformat(), "user_id": user["id"], "plan": user["plan"], "organization_id": user["organization_id"]})

@app.get('/metrics')
def metrics(authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization)
    require_permission(user, "view_metrics")
    with get_conn() as conn:
        users = conn.execute("SELECT COUNT(*) c FROM users WHERE organization_id = ?", (user["organization_id"],)).fetchone()["c"]
        gens = conn.execute("SELECT COUNT(*) c FROM generations WHERE organization_id = ?", (user["organization_id"],)).fetchone()["c"]
        paid = conn.execute("SELECT COUNT(*) c FROM orders WHERE organization_id = ? AND status='paid'", (user["organization_id"],)).fetchone()["c"]
    return JSONResponse({"users": users, "generations": gens, "paid_orders": paid})

@app.post('/generate')
def generate(data: GenerateInput, authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization); check_rate_limit(f"gen:{user['id']}")
    used = monthly_usage(user['id'], user['organization_id']); limit = PLAN_LIMITS[user['plan']]
    if used >= limit: raise HTTPException(status_code=402, detail="Monthly quota exceeded")
    scripts = [build_script(data, i) for i in range(10)]; created_at = utcnow().isoformat()
    with get_conn() as conn:
        conn.execute("INSERT INTO generations(user_id, organization_id, created_at, payload_json, result_json) VALUES (?, ?, ?, ?, ?)", (user['id'], user['organization_id'], created_at, data.model_dump_json(), json.dumps(scripts, ensure_ascii=False)))
    return JSONResponse({"created_at": created_at, "scripts": scripts, "remaining": limit - used - 1})

@app.get('/history')
def history(authorization: str | None = Header(default=None), limit: int = Query(default=20, ge=1, le=100)) -> JSONResponse:
    user = get_current_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("SELECT id, created_at, payload_json, result_json FROM generations WHERE organization_id = ? AND user_id = ? ORDER BY id DESC LIMIT ?", (user['organization_id'], user['id'], limit)).fetchall()
    return JSONResponse({"items": [{"id": r["id"], "created_at": r["created_at"], "payload": json.loads(r["payload_json"]), "scripts": json.loads(r["result_json"])} for r in rows]})

@app.post('/admin/upgrade')
def admin_upgrade(data: UpgradeInput, authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization)
    require_permission(user, "manage_orders")
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (data.user_id,)).fetchone()
        if not target or target["organization_id"] != user["organization_id"]:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("UPDATE users SET plan = ?, updated_at = ? WHERE id = ?", (data.plan, utcnow().isoformat(), data.user_id))
    return JSONResponse({"ok": True, "user_id": data.user_id, "plan": data.plan})

@app.post('/billing/create-order')
def create_order(plan: str = Query(pattern="^(basic|pro)$"), authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization); amount = 2900 if plan == 'basic' else 9900
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO orders(user_id, organization_id, plan, amount, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)", (user['id'], user['organization_id'], plan, amount, utcnow().isoformat()))
    return JSONResponse({"order_id": cur.lastrowid, "amount": amount, "status": "pending"})

@app.post('/billing/webhook')
def billing_webhook(data: BillingWebhookInput, x_signature: str | None = Header(default=None)) -> JSONResponse:
    raw = f"{data.order_id}:{data.status}".encode('utf-8'); expected = hmac.new(BILLING_WEBHOOK_SECRET.encode('utf-8'), raw, hashlib.sha256).hexdigest()
    if not x_signature or not hmac.compare_digest(x_signature, expected): raise HTTPException(status_code=403, detail="Invalid webhook signature")
    with get_conn() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id = ?", (data.order_id,)).fetchone()
        if not order: raise HTTPException(status_code=404, detail="Order not found")
        if data.status == 'paid':
            if order['status'] == 'paid': return JSONResponse({"ok": True, "order_id": data.order_id, "idempotent": True})
            conn.execute("UPDATE orders SET status='paid', paid_at=? WHERE id=?", (utcnow().isoformat(), data.order_id))
            conn.execute("UPDATE users SET plan=?, updated_at=? WHERE id=?", (order['plan'], utcnow().isoformat(), order['user_id']))
        else:
            conn.execute("UPDATE orders SET status='failed' WHERE id=?", (data.order_id,))
    return JSONResponse({"ok": True, "order_id": data.order_id, "status": data.status})
