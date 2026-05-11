import hashlib
import hmac
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import BILLING_WEBHOOK_SECRET, app, get_conn, init_db


def setup_module():
    init_db()
    with get_conn() as conn:
        for t in ["tokens", "webhook_events", "billing_audit_logs", "orders", "generations", "users"]:
            conn.execute(f"DELETE FROM {t}")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def sign(order_id: int, status: str, out_trade_no: str) -> str:
    return hmac.new(BILLING_WEBHOOK_SECRET.encode(), f"{order_id}:{status}:{out_trade_no}".encode(), hashlib.sha256).hexdigest()


def mk_user_and_order(client: TestClient):
    client.post('/auth/register', json={"email": "a@test.com", "password": "12345678"})
    login = client.post('/auth/login', json={"email": "a@test.com", "password": "12345678"})
    token = login.json()['token']
    order = client.post('/billing/create-order?plan=pro&channel=alipay', headers=auth_header(token))
    return token, order.json()


def test_webhook_idempotent_and_invalid_sign_and_out_of_order_and_refund_consistency():
    client = TestClient(app)
    _, order = mk_user_and_order(client)
    oid = order["order_id"]
    out_trade_no = order["payment_params"]["out_trade_no"]
    callback_time = datetime.now(timezone.utc).isoformat()

    bad = client.post('/billing/webhook', json={"order_id": oid, "status": "paid", "out_trade_no": out_trade_no, "callback_time": callback_time}, headers={"x-signature": "bad"})
    assert bad.status_code == 403

    paid_sig = sign(oid, "paid", out_trade_no)
    ok = client.post('/billing/webhook', json={"order_id": oid, "status": "paid", "out_trade_no": out_trade_no, "callback_time": callback_time}, headers={"x-signature": paid_sig})
    assert ok.status_code == 200
    assert ok.json()["status"] == "paid"

    again = client.post('/billing/webhook', json={"order_id": oid, "status": "paid", "out_trade_no": out_trade_no, "callback_time": callback_time}, headers={"x-signature": paid_sig})
    assert again.status_code == 200
    assert again.json()["idempotent"] is True

    failed_sig = sign(oid, "failed", out_trade_no)
    out_of_order = client.post('/billing/webhook', json={"order_id": oid, "status": "failed", "out_trade_no": out_trade_no, "callback_time": callback_time}, headers={"x-signature": failed_sig})
    assert out_of_order.status_code == 200
    assert out_of_order.json()["status"] == "paid"
    assert out_of_order.json()["out_of_order"] is True

    refunded_sig = sign(oid, "refunded", out_trade_no)
    refunded = client.post('/billing/webhook', json={"order_id": oid, "status": "refunded", "out_trade_no": out_trade_no, "callback_time": callback_time}, headers={"x-signature": refunded_sig})
    assert refunded.status_code == 200

    with get_conn() as conn:
        row = conn.execute("SELECT status, refund_status, callback_raw, callback_at FROM orders WHERE id=?", (oid,)).fetchone()
    assert row["status"] == "refunded"
    assert row["refund_status"] == "done"
    assert "refunded" in row["callback_raw"]
    assert row["callback_at"] == callback_time


def test_reconcile_and_retry():
    client = TestClient(app)
    _, order = mk_user_and_order(client)
    day = datetime.now(timezone.utc).date().isoformat()
    r = client.post(f'/billing/reconcile/daily?day={day}', headers={"x-admin-key": "dev-admin-key"})
    assert r.status_code == 200
    rr = client.post('/billing/reconcile/retry', headers={"x-admin-key": "dev-admin-key"})
    assert rr.status_code == 200
