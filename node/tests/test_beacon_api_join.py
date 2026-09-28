import hashlib
import json
import sqlite3
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask

import beacon_api


def _client(tmp_path, monkeypatch):
    db_path = tmp_path / "beacon.db"
    monkeypatch.setattr(beacon_api, "DB_PATH", str(db_path))
    beacon_api.init_beacon_tables(str(db_path))

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(beacon_api.beacon_api)
    return app.test_client()


def _db_status(agent_id):
    conn = sqlite3.connect(beacon_api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT status FROM relay_agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def _set_status(agent_id, status):
    conn = sqlite3.connect(beacon_api.DB_PATH)
    try:
        conn.execute(
            "UPDATE relay_agents SET status = ? WHERE agent_id = ?",
            (status, agent_id),
        )
        conn.commit()
    finally:
        conn.close()


def test_beacon_join_rejects_non_ed25519_pubkey_length(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.post(
        "/beacon/join",
        json={
            "agent_id": "short-key-agent",
            "pubkey_hex": "00",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid pubkey_hex: must be 32 bytes"


def test_beacon_join_accepts_32_byte_ed25519_pubkey(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.post(
        "/beacon/join",
        json={
            "agent_id": "valid-key-agent",
            "pubkey_hex": "11" * 32,
        },
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True


_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
_PUBKEY_HEX = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()


def _join(client, agent_id, pubkey_hex=_PUBKEY_HEX, name=None):
    body = {"agent_id": agent_id, "pubkey_hex": pubkey_hex}
    if name is not None:
        body["name"] = name
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = f"join-{time.time_ns()}"
    message = "\n".join([
        "POST",
        "/beacon/join",
        hashlib.sha256(body_bytes).hexdigest(),
        timestamp,
        nonce,
        agent_id,
    ]).encode("utf-8")
    headers = {
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": _PRIVATE_KEY.sign(message).hex(),
    }
    return client.post(
        "/beacon/join", data=body_bytes, content_type="application/json",
        headers=headers,
    )


def _unsigned_join(client, agent_id, name):
    return client.post(
        "/beacon/join",
        json={"agent_id": agent_id, "pubkey_hex": _PUBKEY_HEX, "name": name},
    )


def test_beacon_join_does_not_unban_banned_agent(tmp_path, monkeypatch):
    """A rejoin must not lift an administrative ban (issue #14589)."""
    client = _client(tmp_path, monkeypatch)

    assert _join(client, "banned-agent").status_code == 200
    # Admin bars the agent out of band.
    _set_status("banned-agent", "banned")

    # Attacker rejoins with the same (immutable) pubkey to self-unban.
    response = _join(client, "banned-agent", name="renamed")

    assert response.status_code == 200
    assert response.get_json()["status"] == "banned"
    assert _db_status("banned-agent") == "banned"


def test_beacon_join_keeps_suspended_and_revoked_status(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    for agent_id, status in (("susp-agent", "suspended"), ("rev-agent", "revoked")):
        assert _join(client, agent_id).status_code == 200
        _set_status(agent_id, status)

        response = _join(client, agent_id)

        assert response.get_json()["status"] == status
        assert _db_status(agent_id) == status


def test_beacon_join_reactivates_inactive_agent(tmp_path, monkeypatch):
    """Non-protected statuses (e.g. inactive) still come back online on rejoin."""
    client = _client(tmp_path, monkeypatch)

    assert _join(client, "idle-agent").status_code == 200
    _set_status("idle-agent", "inactive")

    response = _join(client, "idle-agent")

    assert response.get_json()["status"] == "active"
    assert _db_status("idle-agent") == "active"


def test_beacon_join_rejects_unsigned_existing_agent_update(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _join(client, "existing-agent", name="Original").status_code == 200
    _set_status("existing-agent", "inactive")

    response = _unsigned_join(client, "existing-agent", "Attacker Renamed")

    assert response.status_code == 401
    assert _db_status("existing-agent") == "inactive"
    conn = sqlite3.connect(beacon_api.DB_PATH)
    try:
        name = conn.execute(
            "SELECT name FROM relay_agents WHERE agent_id = ?",
            ("existing-agent",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert name == "Original"


def test_beacon_join_accepts_valid_signature_for_existing_agent(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _join(client, "existing-agent", name="Original").status_code == 200
    _set_status("existing-agent", "inactive")

    response = _join(client, "existing-agent", name="Updated")

    assert response.status_code == 200
    assert response.get_json()["status"] == "active"
    assert _db_status("existing-agent") == "active"
    conn = sqlite3.connect(beacon_api.DB_PATH)
    try:
        name = conn.execute(
            "SELECT name FROM relay_agents WHERE agent_id = ?",
            ("existing-agent",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert name == "Updated"
