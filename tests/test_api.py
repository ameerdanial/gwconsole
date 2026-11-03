"""API tests: login, roles and permissions, forced password change, admin endpoints."""
H = {"X-GWC": "1"}


def login(c, user, pw):
    return c.post("/api/login", json={"user": user, "password": pw})


def test_login_and_roles(client):
    assert login(client, "root", "bad").status_code == 401
    r = login(client, "root", "RootPass1234")
    assert r.status_code == 200 and r.json()["role"] == "superadmin"
    assert client.get("/api/me").json()["version"]
    # create an operator and a viewer
    op = client.post("/api/admin/users", json={"username": "op1", "role": "operator"}, headers=H).json()["temp_password"]
    client.post("/api/admin/users", json={"username": "vw1", "role": "viewer", "password": "Viewer12345"}, headers=H)
    users = client.get("/api/admin/users").json()["items"]
    assert {u["username"]: u["role"] for u in users} == {"op1": "operator", "root": "superadmin", "vw1": "viewer"}

    # new user must change password before anything else
    client.cookies.clear()
    assert login(client, "op1", op).json()["must_change"] is True
    r = client.get("/api/overview")
    assert r.status_code == 403 and r.json()["must_change"]
    assert client.post("/api/account/password", json={"current": op, "new": "Operator2026x"}, headers=H).json()["ok"]
    assert client.get("/api/alerts/summary").status_code == 200
    assert client.get("/api/admin/users").status_code == 403                       # operator: no admin

    client.cookies.clear()
    login(client, "vw1", "Viewer12345")
    client.post("/api/account/password", json={"current": "Viewer12345", "new": "Viewer2026xx"}, headers=H)
    r = client.post("/api/mutes", json={"match": "node:x", "minutes": 30}, headers=H)
    assert r.status_code == 403 and "needs operator" in r.json()["error"]
    assert client.post("/api/haproxy/x/service", json={"action": "reload"}, headers=H).status_code == 403


def test_csrf_header_required(client):
    login(client, "root", "RootPass1234")
    assert client.post("/api/admin/users", json={"username": "z1", "role": "viewer"}).status_code == 403


def test_settings_endpoints(client):
    login(client, "root", "RootPass1234")
    assert client.put("/api/admin/general", json={"alert_interval": 45}, headers=H).json()["settings"]["alert_interval"] == 45
    r = client.post("/api/admin/cf-accounts", json={"name": "main", "account_id": "0123456789abcdef0123456789abcdef", "token": "t"}, headers=H)
    assert r.json()["ok"]
    assert client.get("/api/admin/cf-accounts").json()["items"][0]["has_token"] is True
    assert client.get("/api/inventory").json()["cf_accounts"] == ["main"]
    r = client.post("/api/admin/nodes", json={"kind": "haproxy", "name": "hp1", "host": "10.0.0.1"}, headers=H)
    assert r.status_code == 400 and "host key" in r.json()["error"]
    r = client.put("/api/admin/notify/discord", json={"enabled": True, "webhook": "https://evil.example/x"}, headers=H)
    assert r.status_code == 400
    me = [u for u in client.get("/api/admin/users").json()["items"] if u["username"] == "root"][0]
    assert client.delete(f"/api/admin/users/{me['id']}", headers=H).status_code == 400   # can't delete yourself
