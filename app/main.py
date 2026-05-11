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
ADMIN_KEY = os.getenv("ADMIN_KEY", "dev-admin-key")
TOKEN_TTL_DAYS = int(os.getenv("TOKEN_TTL_DAYS", "30"))
BILLING_WEBHOOK_SECRET = os.getenv("BILLING_WEBHOOK_SECRET", "dev-webhook-secret")

PLAN_LIMITS = {"free": 2, "basic": 50, "pro": 300}
RATE_LIMIT_PER_MINUTE = 30
GEN_RATE_BUCKET: dict[str, deque] = defaultdict(deque)
STATUS_ORDER = {"pending": 0, "paid": 1, "refunded": 2, "failed": 2}

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
    status: str = Field(pattern="^(paid|failed|refunded)$")
    out_trade_no: str = Field(min_length=6, max_length=64)
    callback_time: str


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


def validate_admin_key(x_admin_key: str | None) -> None:
    if not x_admin_key or not hmac.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin key")


def assert_secure_config() -> None:
    if APP_ENV == "prod" and ADMIN_KEY == "dev-admin-key":
        raise RuntimeError("ADMIN_KEY must be set in prod")


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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                out_trade_no TEXT,
                callback_raw TEXT,
                callback_at TEXT,
                refund_status TEXT NOT NULL DEFAULT 'none',
                created_at TEXT NOT NULL,
                paid_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_key TEXT PRIMARY KEY,
                order_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS billing_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                stage TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
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
        row = conn.execute("SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.token = ? AND t.revoked = 0 AND t.expires_at > ?", (token, utcnow().isoformat())).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return row


def monthly_usage(user_id: int) -> int:
    first_day = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as c FROM generations WHERE user_id = ? AND created_at >= ?", (user_id, first_day)).fetchone()
    return int(row["c"])


def build_script(data: GenerateInput, idx: int) -> dict[str, Any]:
    hooks = {"restaurant": ["附近吃什么？", "这家店被低估了", "人均不高但很稳"], "beauty": ["做完变化太明显了", "学生党也能做", "本周预约快满了"]}
    hook = hooks[data.industry][idx % 3]
    return {"title": f"{data.business_name}选题{idx + 1}: {hook}", "hook_3s": f"{hook}，今天带你看{data.main_offer}", "voiceover": f"这里是{data.business_name}，主打{data.main_offer}，适合{data.audience}，人均约{data.avg_ticket}。本期目标：{data.goal}。", "shots": ["门头环境", "过程特写", "结果反馈"], "duration_sec": 20 + (idx % 3) * 5, "cta": "评论区回复关键词，领取到店福利"}


def sign_payload(order_id: int, status: str, out_trade_no: str) -> str:
    raw = f"{order_id}:{status}:{out_trade_no}".encode("utf-8")
    return hmac.new(BILLING_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def write_audit(conn: sqlite3.Connection, order_id: int, stage: str, detail: dict[str, Any]) -> None:
    conn.execute("INSERT INTO billing_audit_logs(order_id, stage, detail, created_at) VALUES (?, ?, ?, ?)", (order_id, stage, json.dumps(detail, ensure_ascii=False), utcnow().isoformat()))


def apply_order_status(conn: sqlite3.Connection, order: sqlite3.Row, status: str) -> tuple[str, bool]:
    current = order["status"]
    if current in {"paid", "refunded"} and status == "failed":
        return current, True
    if STATUS_ORDER[status] < STATUS_ORDER[current]:
        return current, True
    if status == "paid":
        conn.execute("UPDATE orders SET status='paid', paid_at=? WHERE id=?", (utcnow().isoformat(), order["id"]))
        conn.execute("UPDATE users SET plan=?, updated_at=? WHERE id=?", (order["plan"], utcnow().isoformat(), order["user_id"]))
    elif status == "refunded":
        conn.execute("UPDATE orders SET status='refunded', refund_status='done' WHERE id=?", (order["id"],))
    else:
        conn.execute("UPDATE orders SET status='failed' WHERE id=?", (order["id"],))
    return status, False


@app.post("/billing/create-order")
def create_order(plan: str = Query(pattern="^(basic|pro)$"), channel: str = Query(default="alipay", pattern="^(alipay|wechat)$"), authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization)
    amount = 2900 if plan == "basic" else 9900
    out_trade_no = f"T{user['id']}{int(datetime.now().timestamp())}{secrets.randbelow(1000)}"
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO orders(user_id, plan, amount, status, out_trade_no, created_at) VALUES (?, ?, ?, 'pending', ?, ?)", (user["id"], plan, amount, out_trade_no, utcnow().isoformat()))
    pay_params = {
        "channel": channel,
        "out_trade_no": out_trade_no,
        "amount": amount,
        "qr_link": f"https://pay.example.com/{channel}/qrcode/{out_trade_no}",
        "prepay_info": {"nonce": secrets.token_hex(8), "timestamp": int(datetime.now().timestamp())},
    }
    return JSONResponse({"order_id": cur.lastrowid, "status": "pending", "payment_params": pay_params})


@app.post("/billing/webhook")
async def billing_webhook(request: Request, x_signature: str | None = Header(default=None), x_idempotency_key: str | None = Header(default=None)) -> JSONResponse:
    body = await request.body()
    payload = BillingWebhookInput(**json.loads(body.decode("utf-8")))

    expected = sign_payload(payload.order_id, payload.status, payload.out_trade_no)
    if not x_signature or not hmac.compare_digest(x_signature, expected):
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

    idempotency_key = x_idempotency_key or f"{payload.order_id}:{payload.status}:{payload.out_trade_no}"
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM webhook_events WHERE event_key=?", (idempotency_key,)).fetchone():
            write_audit(conn, payload.order_id, "idempotent_hit", {"key": idempotency_key})
            return JSONResponse({"ok": True, "order_id": payload.order_id, "idempotent": True})
        conn.execute("INSERT INTO webhook_events(event_key, order_id, status, created_at) VALUES (?, ?, ?, ?)", (idempotency_key, payload.order_id, payload.status, utcnow().isoformat()))

        order = conn.execute("SELECT * FROM orders WHERE id = ?", (payload.order_id,)).fetchone()
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        write_audit(conn, payload.order_id, "signature_ok", {"event_key": idempotency_key})

        final_status, out_of_order = apply_order_status(conn, order, payload.status)
        conn.execute("UPDATE orders SET out_trade_no=?, callback_raw=?, callback_at=?, refund_status=? WHERE id=?", (payload.out_trade_no, body.decode("utf-8"), payload.callback_time, "done" if final_status == "refunded" else order["refund_status"], payload.order_id))
        write_audit(conn, payload.order_id, "status_transition", {"from": order["status"], "to": final_status, "out_of_order": out_of_order})
    return JSONResponse({"ok": True, "order_id": payload.order_id, "status": final_status, "out_of_order": out_of_order})


@app.post("/billing/reconcile/daily")
def reconcile_daily(day: str = Query(..., description="YYYY-MM-DD"), x_admin_key: str | None = Header(default=None)) -> JSONResponse:
    validate_admin_key(x_admin_key)
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE substr(created_at,1,10)=?", (day,)).fetchall()
        anomalies: list[int] = []
        for r in rows:
            remote_status = "paid" if r["out_trade_no"] and str(r["out_trade_no"]).endswith("0") else r["status"]
            if remote_status != r["status"]:
                anomalies.append(r["id"])
                write_audit(conn, r["id"], "reconcile_mismatch", {"local": r["status"], "remote": remote_status})
        conn.execute("CREATE TABLE IF NOT EXISTS billing_reconcile_retry(order_id INTEGER PRIMARY KEY, retry_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL)")
        for oid in anomalies:
            conn.execute("INSERT INTO billing_reconcile_retry(order_id, retry_count, last_error, updated_at) VALUES (?, 0, ?, ?) ON CONFLICT(order_id) DO UPDATE SET last_error=excluded.last_error, updated_at=excluded.updated_at", (oid, "status_mismatch", utcnow().isoformat()))
    return JSONResponse({"checked": len(rows), "anomalies": anomalies})


@app.post("/billing/reconcile/retry")
def reconcile_retry(x_admin_key: str | None = Header(default=None)) -> JSONResponse:
    validate_admin_key(x_admin_key)
    fixed = []
    with get_conn() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS billing_reconcile_retry(order_id INTEGER PRIMARY KEY, retry_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL)")
        retries = conn.execute("SELECT * FROM billing_reconcile_retry").fetchall()
        for row in retries:
            order = conn.execute("SELECT * FROM orders WHERE id=?", (row["order_id"],)).fetchone()
            if not order:
                continue
            conn.execute("UPDATE billing_reconcile_retry SET retry_count=retry_count+1, updated_at=? WHERE order_id=?", (utcnow().isoformat(), row["order_id"]))
            if order["status"] == "pending":
                conn.execute("UPDATE orders SET status='failed' WHERE id=?", (order["id"],))
                fixed.append(order["id"])
                write_audit(conn, order["id"], "retry_fixed", {"new_status": "failed"})
    return JSONResponse({"fixed": fixed})

# existing endpoints omitted for brevity below
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html", context={"token_ttl_days": TOKEN_TTL_DAYS})

@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "env": APP_ENV})

@app.get("/metrics")
def metrics(x_admin_key: str | None = Header(default=None)) -> JSONResponse:
    validate_admin_key(x_admin_key)
    with get_conn() as conn:
        users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        gens = conn.execute("SELECT COUNT(*) c FROM generations").fetchone()["c"]
        paid = conn.execute("SELECT COUNT(*) c FROM orders WHERE status='paid'").fetchone()["c"]
    return JSONResponse({"users": users, "generations": gens, "paid_orders": paid})

@app.post('/auth/register')
def register(data: RegisterInput) -> JSONResponse:
    now = utcnow().isoformat()
    salt, pwd_hash = create_password_fields(data.password)
    with get_conn() as conn:
        try:
            cur = conn.execute("INSERT INTO users(email, password_salt, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (data.email, salt, pwd_hash, now, now))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Email already exists")
    return JSONResponse({"user_id": cur.lastrowid, "plan": "free"})

@app.post('/auth/login')
def login(data: LoginInput) -> JSONResponse:
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
        if not user or not verify_password(data.password, user['password_salt'], user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = secrets.token_urlsafe(24)
        now = utcnow()
        expires_at = now + timedelta(days=TOKEN_TTL_DAYS)
        conn.execute("INSERT INTO tokens(token, user_id, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)", (token, user['id'], now.isoformat(), expires_at.isoformat()))
    return JSONResponse({"token": token, "token_expires_at": expires_at.isoformat(), "user_id": user['id'], "plan": user['plan']})

@app.post('/generate')
def generate(data: GenerateInput, authorization: str | None = Header(default=None)) -> JSONResponse:
    user = get_current_user(authorization)
    check_rate_limit(f"gen:{user['id']}")
    used = monthly_usage(user['id'])
    limit = PLAN_LIMITS[user['plan']]
    if used >= limit:
        raise HTTPException(status_code=402, detail='Monthly quota exceeded')
    scripts = [build_script(data, i) for i in range(10)]
    with get_conn() as conn:
        conn.execute("INSERT INTO generations(user_id, created_at, payload_json, result_json) VALUES (?, ?, ?, ?)", (user['id'], utcnow().isoformat(), data.model_dump_json(), json.dumps(scripts, ensure_ascii=False)))
    return JSONResponse({"scripts": scripts, "remaining": limit - used - 1})

@app.post('/admin/upgrade')
def admin_upgrade(data: UpgradeInput, x_admin_key: str | None = Header(default=None)) -> JSONResponse:
    validate_admin_key(x_admin_key)
    with get_conn() as conn:
        updated = conn.execute("UPDATE users SET plan = ?, updated_at = ? WHERE id = ?", (data.plan, utcnow().isoformat(), data.user_id)).rowcount
    if not updated:
        raise HTTPException(status_code=404, detail='User not found')
    return JSONResponse({"ok": True})
