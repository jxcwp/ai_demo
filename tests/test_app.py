import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import BILLING_WEBHOOK_SECRET, app, get_conn, init_db


def setup_module():
    init_db()
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
    with TestClient(app) as client:

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["version"] == "0.2.1"

        reg = client.post('/auth/register', json={"email": "a@test.com", "password": "12345678"})
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

        ok = client.post('/billing/webhook', json={"order_id": order_id, "status": "paid"}, headers={"x-signature": sign(order_id, 'paid')})
        assert ok.status_code == 200


        t = client.post('/admin/templates', json={"industry": "restaurant", "name": "团购模板", "content": {"hook": "今天吃什么"}}, headers={"x-admin-key": "dev-admin-key"})
        assert t.status_code == 200

        tlist = client.get('/templates?industry=restaurant')
        assert tlist.status_code == 200
        assert len(tlist.json()['items']) >= 1

        history = client.get('/history', headers=auth_header(token))
        gid = history.json()['items'][0]['id']
        fav = client.post('/favorites', json={"generation_id": gid, "note": "高转化"}, headers=auth_header(token))
        assert fav.status_code == 200

        favlist = client.get('/favorites', headers=auth_header(token))
        assert favlist.status_code == 200
        assert len(favlist.json()['items']) >= 1

        analytics = client.get('/analytics/summary', headers=auth_header(token))
        assert analytics.status_code == 200
        assert analytics.json()['total_generations'] >= 1

        exported = client.get(f'/history/{gid}/export?format=markdown', headers=auth_header(token))
        assert exported.status_code == 200
        assert '# 生成记录' in exported.json()['content']

        sch = client.post('/schedules', json={"date": "2026-05-12", "theme": "探店口播", "channel": "douyin"}, headers=auth_header(token))
        assert sch.status_code == 200
        sid = sch.json()['id']

        sch_list = client.get('/schedules', headers=auth_header(token))
        assert sch_list.status_code == 200
        assert len(sch_list.json()['items']) >= 1

        sch_done = client.patch(f'/schedules/{sid}/status?status=done', headers=auth_header(token))
        assert sch_done.status_code == 200

        sch_done_list = client.get('/schedules?status=done', headers=auth_header(token))
        assert sch_done_list.status_code == 200
        users = client.get('/admin/users', headers={"x-admin-key": "dev-admin-key"})
        assert users.status_code == 200
        ujson = users.json()
        assert len(ujson['items']) >= 1
        assert 'total' in ujson and 'offset' in ujson

        orders = client.get('/admin/orders?limit=10&offset=0', headers={"x-admin-key": "dev-admin-key"})
        assert orders.status_code == 200
        ojson = orders.json()
        assert len(ojson['items']) >= 1
        assert 'total' in ojson

        paid_orders = client.get('/admin/orders?status=paid&limit=10&offset=0', headers={"x-admin-key": "dev-admin-key"})
        assert paid_orders.status_code == 200
