import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import BILLING_WEBHOOK_SECRET, app, get_conn, init_db


def setup_module():
    init_db()
    with get_conn() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM favorites")
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
    history = client.get('/history', headers=auth_header(token)).json()
    gen_id = history["items"][0]["id"]
    fav = client.post('/favorites', json={"generation_id": gen_id}, headers=auth_header(token))
    assert fav.status_code == 200

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

    summary = client.get('/analytics/summary?window=week', headers=auth_header(token))
    assert summary.status_code == 200
    body = summary.json()
    assert body["funnel_counts"]["register"] >= 1
    assert body["funnel_counts"]["favorite"] >= 1


def test_analytics_empty_data():
    client = TestClient(app)
    with get_conn() as conn:
        conn.execute("DELETE FROM events")
    reg = client.post('/auth/register', json={"email": "empty@test.com", "password": "12345678"})
    assert reg.status_code == 200
    login = client.post('/auth/login', json={"email": "empty@test.com", "password": "12345678"})
    token = login.json()['token']
    with get_conn() as conn:
        conn.execute("DELETE FROM events")
    summary = client.get('/analytics/summary?window=day', headers=auth_header(token))
    assert summary.status_code == 200
    assert summary.json()["active_users"] == 0
    assert summary.json()["funnel_rates"]["payment_success"] == 0.0


def test_admin_trends_window_aggregation():
    client = TestClient(app)
    reg = client.post('/auth/register', json={"email": "trend@test.com", "password": "12345678"})
    user_id = reg.json()["user_id"]
    with get_conn() as conn:
        conn.execute("DELETE FROM events WHERE user_id=?", (user_id,))
        conn.execute(
            "INSERT INTO events(user_id, event_type, event_at, metadata_json) VALUES (?, 'generate', datetime('now'), '{}')",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO events(user_id, event_type, event_at, metadata_json) VALUES (?, 'payment_success', datetime('now'), '{}')",
            (user_id,),
        )
    trends = client.get('/admin/analytics/trends?days=7', headers={"x-admin-key": "dev-admin-key"})
    assert trends.status_code == 200
    points = trends.json()["points"]
    assert len(points) == 7
    assert any((p["generate"] >= 1 or p["payment_success"] >= 1) for p in points)
