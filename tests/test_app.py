import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import BILLING_WEBHOOK_SECRET, app, get_conn


def setup_module():
    with get_conn() as conn:
        conn.execute("DELETE FROM tokens")
        conn.execute("DELETE FROM orders")
        conn.execute("DELETE FROM generations")
        conn.execute("DELETE FROM users")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def sign(order_id: int, status: str) -> str:
    return hmac.new(BILLING_WEBHOOK_SECRET.encode(), f"{order_id}:{status}".encode(), hashlib.sha256).hexdigest()


def test_full_flow():
    client = TestClient(app)

    reg = client.post('/auth/register', json={"email": "a@test.com", "password": "12345678"})
    assert reg.status_code == 200
    user_id = reg.json()['user_id']

    login = client.post('/auth/login', json={"email": "a@test.com", "password": "12345678"})
    token = login.json()['token']

    payload = {
        "industry": "restaurant",
        "business_name": "A店",
        "main_offer": "双人餐",
        "avg_ticket": "88",
        "audience": "白领",
        "goal": "引流",
    }
    assert client.post('/generate', json=payload, headers=auth_header(token)).status_code == 200

    up = client.post('/admin/upgrade', json={"user_id": user_id, "plan": "basic"}, headers={"x-admin-key": "dev-admin-key"})
    assert up.status_code == 200

    order = client.post('/billing/create-order?plan=pro', headers=auth_header(token))
    order_id = order.json()['order_id']

    bad = client.post('/billing/webhook', json={"order_id": order_id, "status": "paid"}, headers={"x-signature": "bad"})
    assert bad.status_code == 403

    ok = client.post('/billing/webhook', json={"order_id": order_id, "status": "paid"}, headers={"x-signature": sign(order_id, 'paid')})
    assert ok.status_code == 200

    again = client.post('/billing/webhook', json={"order_id": order_id, "status": "paid"}, headers={"x-signature": sign(order_id, 'paid')})
    assert again.status_code == 200
    assert again.json()['idempotent'] is True

    metrics = client.get('/metrics', headers={"x-admin-key": "dev-admin-key"})
    assert metrics.status_code == 200
