import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import BILLING_WEBHOOK_SECRET, app, get_conn, init_db


def setup_module():
    init_db()
    with get_conn() as conn:
        conn.execute("DELETE FROM tokens")
        conn.execute("DELETE FROM memberships")
        conn.execute("DELETE FROM orders")
        conn.execute("DELETE FROM generations")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM organizations")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def sign(order_id: int, status: str) -> str:
    return hmac.new(BILLING_WEBHOOK_SECRET.encode(), f"{order_id}:{status}".encode(), hashlib.sha256).hexdigest()


def test_permission_and_org_isolation():
    client = TestClient(app)
    r1 = client.post('/auth/register', json={"email": "a@test.com", "password": "12345678"}).json()
    t1 = client.post('/auth/login', json={"email": "a@test.com", "password": "12345678"}).json()["token"]

    r2 = client.post('/auth/register', json={"email": "b@test.com", "password": "12345678"}).json()
    t2 = client.post('/auth/login', json={"email": "b@test.com", "password": "12345678"}).json()["token"]

    payload = {"industry": "restaurant", "business_name": "A店", "main_offer": "双人餐", "avg_ticket": "88", "audience": "白领", "goal": "引流"}
    assert client.post('/generate', json=payload, headers=auth_header(t1)).status_code == 200

    history2 = client.get('/history', headers=auth_header(t2)).json()["items"]
    assert history2 == []

    # admin endpoint now uses token + permission instead of x-admin-key
    deny = client.post('/admin/upgrade', json={"user_id": r1["user_id"], "plan": "basic"})
    assert deny.status_code == 401

    ok = client.post('/admin/upgrade', json={"user_id": r1["user_id"], "plan": "basic"}, headers=auth_header(t1))
    assert ok.status_code == 200

    # cross-organization user update blocked
    cross = client.post('/admin/upgrade', json={"user_id": r2["user_id"], "plan": "pro"}, headers=auth_header(t1))
    assert cross.status_code == 404

    order = client.post('/billing/create-order?plan=pro', headers=auth_header(t1)).json()
    bad = client.post('/billing/webhook', json={"order_id": order['order_id'], "status": "paid"}, headers={"x-signature": "bad"})
    assert bad.status_code == 403
    paid = client.post('/billing/webhook', json={"order_id": order['order_id'], "status": "paid"}, headers={"x-signature": sign(order['order_id'], 'paid')})
    assert paid.status_code == 200


def test_role_permission_matrix():
    client = TestClient(app)
    # create a third user/org and replace owner role with analyst (metrics-only)
    reg = client.post('/auth/register', json={"email": "c@test.com", "password": "12345678"}).json()
    token = client.post('/auth/login', json={"email": "c@test.com", "password": "12345678"}).json()["token"]

    with get_conn() as conn:
        analyst = conn.execute("SELECT id FROM roles WHERE name='analyst'").fetchone()["id"]
        conn.execute("UPDATE memberships SET role_id = ? WHERE user_id = ?", (analyst, reg["user_id"]))

    assert client.get('/metrics', headers=auth_header(token)).status_code == 200
    assert client.post('/admin/upgrade', json={"user_id": reg["user_id"], "plan": "pro"}, headers=auth_header(token)).status_code == 403
