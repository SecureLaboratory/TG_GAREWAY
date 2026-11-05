"""Admin events list: only login and admin events from the audit log, newest first, no other fields."""
import json

from tgviewer.config import settings
from tgviewer.routes import admin


def test_recent_events_shows_only_auth_and_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    (tmp_path / "audit").mkdir()
    lines = [
        {"@timestamp": "t1", "event.action": "auth.login_failed", "username": "x", "reason": "unknown_or_disabled"},
        {"@timestamp": "t2", "event.action": "telegram.code_requested", "user_id": 2, "phone": "+380***00"},
        {"@timestamp": "t3", "event.action": "scan.verdict", "sha256": "ab"},
        "not json",
        {"@timestamp": "t4", "event.action": "auth.login", "user_id": 2, "mfa": "totp"},
        {"@timestamp": "t5", "event.action": "admin.user_created", "actor_id": 1, "user_id": 3, "role": "user"},
    ]
    (tmp_path / "audit" / "audit.jsonl").write_text(
        "\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    events = admin._recent_events(10)
    assert [e["event.action"] for e in events] == ["admin.user_created", "auth.login", "auth.login_failed"]
    assert all("phone" not in e for e in events)
    assert len(admin._recent_events(1)) == 1


def test_recent_events_without_log(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    assert admin._recent_events(10) == []
