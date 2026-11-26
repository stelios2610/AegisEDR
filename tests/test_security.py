"""Security behavior of the console and the shared agent helpers."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="aegis-test-"))
os.environ["AEGISEDR_DB"] = str(TMP / "aegis.db")
os.environ["AEGISEDR_SECRET"] = "test-secret-key-must-be-32-characters-min"
os.environ["AEGISEDR_SECRET_FILE"] = str(TMP / "secret")
os.environ["AEGISEDR_SETUP_TOKEN_FILE"] = str(TMP / "setup_token")
os.environ["AEGISEDR_TLS_CERT"] = str(TMP / "missing.pem")
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

from fastapi.testclient import TestClient

from core.database import hash_agent_token
from core.tasks import mark_stale_endpoints_offline
from main import app
from web.security import client_ip
import edr_common


def _client():
    return TestClient(app)


def _admin(client: TestClient):
    token_path = Path(os.environ["AEGISEDR_SETUP_TOKEN_FILE"])
    if token_path.exists():
        created = client.post("/setup", data={
            "setup_token": token_path.read_text().strip(),
            "username": "secadmin",
            "password": "correct-horse-battery",
        }, follow_redirects=False)
        assert created.status_code == 302
    logged = client.post("/login", data={
        "username": "secadmin",
        "password": "correct-horse-battery",
    }, follow_redirects=False)
    assert logged.status_code == 302
    assert "aegisedr_token" in logged.cookies


def test_no_default_admin_and_setup_token_is_single_use():
    with _client() as client:
        assert client.get("/login", follow_redirects=False).status_code == 302
        page = client.get("/setup")
        assert page.status_code == 200
        assert "AegisEDR2024" not in page.text
        _admin(client)
        again = client.post("/setup", data={
            "setup_token": "nope-nope-nope-nope",
            "username": "other",
            "password": "correct-horse-battery",
        }, follow_redirects=False)
        assert again.status_code == 302
        assert not Path(os.environ["AEGISEDR_SETUP_TOKEN_FILE"]).exists()


def test_enrollment_does_not_hand_out_an_existing_token():
    with _client() as client:
        _admin(client)
        created = client.post("/api/enrollment/codes", json={"label": "lab", "max_uses": 1, "ttl_hours": 2})
        assert created.status_code == 200
        code = created.json()["code"]

        registered = client.post("/api/endpoints/register", json={
            "hostname": "workstation",
            "ip_address": "203.0.113.50",
            "os_type": "Linux",
            "enrollment_code": code,
        })
        assert registered.status_code == 200
        body = registered.json()
        token = body["token"]
        assert body["approved"] is False

        missing = client.post("/api/endpoints/register", json={
            "hostname": "workstation",
            "ip_address": "203.0.113.50",
            "os_type": "Linux",
        })
        assert missing.status_code == 401

        stolen = client.post("/api/endpoints/register", json={
            "hostname": "workstation",
            "ip_address": "10.0.0.8",
            "enrollment_code": code,
        })
        assert stolen.status_code == 403

        again = client.post(
            "/api/endpoints/register",
            json={"hostname": "workstation", "os_type": "Linux"},
            headers={"X-Agent-Token": token},
        )
        assert again.status_code == 200
        assert "token" not in again.json()

        import sqlite3
        rows = sqlite3.connect(os.environ["AEGISEDR_DB"]).execute(
            "SELECT agent_token_hash FROM endpoints"
        ).fetchall()
        assert rows
        assert all(row[0] == hash_agent_token(token) for row in rows)
        assert token not in rows[0][0]


def test_commands_survive_and_restore_waits_for_the_agent():
    with _client() as client:
        _admin(client)
        code = client.post("/api/enrollment/codes", json={"max_uses": 2, "ttl_hours": 2}).json()["code"]
        registered = client.post("/api/endpoints/register", json={
            "hostname": "scanner", "os_type": "Linux", "enrollment_code": code,
        }).json()
        token = registered["token"]
        endpoint_id = registered["endpoint_id"]
        assert client.post(f"/api/endpoints/{endpoint_id}/adopt").status_code == 200
        beat = client.post("/api/endpoints/heartbeat", headers={"X-Agent-Token": token})
        assert beat.status_code == 200
        assert beat.json()["policy"]["auto_quarantine"] in ("0", "1")

        started = client.post("/api/scan/start", json={"endpoint_id": endpoint_id, "scan_type": "quick"})
        assert started.status_code == 200
        commands = client.get("/api/agent/commands", headers={"X-Agent-Token": token}).json()["commands"]
        assert len(commands) == 1
        assert commands[0]["command"] == "scan"
        assert commands[0]["payload"]["scan_job_id"] == started.json()["job_id"]

        added = client.post("/api/quarantine/add", headers={"X-Agent-Token": token}, json={
            "original_path": "/home/user/eicar.com",
            "quarantine_path": "/var/lib/aegisedr-agent/quarantine/1_eicar.com.quar",
            "file_hash": "a" * 64,
            "file_size": 68,
        })
        item_id = added.json()["id"]
        queued = client.post(f"/api/quarantine/{item_id}/restore")
        assert queued.json()["status"] == "queued"
        import sqlite3
        restored = sqlite3.connect(os.environ["AEGISEDR_DB"]).execute(
            "SELECT restored FROM quarantine WHERE id=?", (item_id,)
        ).fetchone()[0]
        assert restored == 0
        restore_cmd = client.get("/api/agent/commands", headers={"X-Agent-Token": token}).json()["commands"]
        assert restore_cmd[0]["command"] == "restore"
        done = client.post(
            f"/api/agent/commands/{restore_cmd[0]['id']}/result",
            headers={"X-Agent-Token": token},
            json={"status": "done"},
        )
        assert done.status_code == 200
        restored = sqlite3.connect(os.environ["AEGISEDR_DB"]).execute(
            "SELECT restored FROM quarantine WHERE id=?", (item_id,)
        ).fetchone()[0]
        assert restored == 1


def test_stale_endpoint_goes_offline_and_real_ip_is_used():
    class _Request:
        def __init__(self, host, headers):
            self.client = type("C", (), {"host": host})()
            self.headers = headers

    assert client_ip(_Request("127.0.0.1", {"x-real-ip": "198.51.100.20"})) == "198.51.100.20"
    assert client_ip(_Request("203.0.113.9", {"x-real-ip": "198.51.100.20"})) == "203.0.113.9"

    import sqlite3
    rate_db = sqlite3.connect(os.environ["AEGISEDR_DB"])
    rate_db.execute("DELETE FROM rate_limits")
    rate_db.commit()
    rate_db.close()
    with _client() as client:
        _admin(client)
        code = client.post("/api/enrollment/codes", json={"max_uses": 1, "ttl_hours": 1}).json()["code"]
        registered = client.post("/api/endpoints/register", json={
            "hostname": "stale", "os_type": "Linux", "enrollment_code": code,
        })
        assert registered.status_code == 200, registered.text
        token = registered.json()["token"]
    db = sqlite3.connect(os.environ["AEGISEDR_DB"])
    db.execute(
        "UPDATE endpoints SET approved=1, status='online', last_seen='2000-01-01 00:00:00' WHERE hostname='stale'"
    )
    db.commit()
    db.close()
    import asyncio
    asyncio.run(mark_stale_endpoints_offline())
    import sqlite3
    status = sqlite3.connect(os.environ["AEGISEDR_DB"]).execute(
        "SELECT status FROM endpoints WHERE hostname='stale'"
    ).fetchone()[0]
    assert status == "offline"
    with _client() as client:
        assert client.post("/api/endpoints/heartbeat", headers={"X-Agent-Token": token}).status_code == 200


def test_login_rate_limit_is_per_real_ip():
    with _client() as client:
        _admin(client)
        last = None
        for _ in range(11):
            last = client.post("/login", data={"username": "secadmin", "password": "wrong-password-value"},
                               headers={"X-Real-IP": "198.51.100.8"})
        # The test client is not loopback, so X-Real-IP is not trusted and the
        # bucket is the peer. Eleven failures from one peer are still limited.
        assert last.status_code == 429


def test_ransomware_entropy_is_a_burst_not_a_single_file(tmp_path=None):
    folder = TMP / "docs"
    folder.mkdir()
    benign = folder / "photo.jpg"
    benign.write_bytes(os.urandom(8192))
    assert edr_common.check_ransomware(str(benign)) is None
    note = folder / "how_to_decrypt.txt"
    note.write_text("pay")
    assert "Ransom note" in edr_common.check_ransomware(str(note))
    for index in range(19):
        path = folder / f"file{index}.txt"
        path.write_bytes(os.urandom(8192))
        assert edr_common.check_ransomware(str(path)) is None
    last = folder / "file-last.txt"
    last.write_bytes(os.urandom(8192))
    assert "Burst" in (edr_common.check_ransomware(str(last)) or "")


def test_secret_is_not_regenerated_when_it_cannot_be_stored():
    import subprocess
    code = (
        "import os, sys\n"
        "os.environ.pop('AEGISEDR_SECRET', None)\n"
        "os.environ['AEGISEDR_SECRET_FILE'] = '/proc/does-not-exist/secret'\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "import config\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode != 0
    assert "Cannot persist the console secret" in (result.stderr + result.stdout)
