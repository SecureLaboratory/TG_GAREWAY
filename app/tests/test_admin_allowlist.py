"""ADMIN_ALLOWED_IPS: the admin area through the public address, only from listed client addresses."""
import ipaddress
from types import SimpleNamespace

import pytest

from tgviewer import config, deps
from tgviewer.config import settings


def req(ip: str | None, header: str | None = None):
    return SimpleNamespace(client=SimpleNamespace(host=ip) if ip else None,
                           headers={deps.ADMIN_CHANNEL_HEADER: header} if header else {})


def nets(*cidrs):
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def test_default_is_admin_entrance_only(monkeypatch):
    monkeypatch.setattr(settings, "admin_allowed_ips", [])
    assert deps.via_admin_channel(req("203.0.113.7", "1"))        # localhost admin listener
    assert not deps.via_admin_channel(req("203.0.113.7"))
    assert not deps.via_admin_channel(req("127.0.0.1"))           # no implicit trust in any address
    assert not deps.via_admin_channel(req(None))
    assert not deps.via_admin_channel(req("203.0.113.7", "yes"))  # only the exact value counts


def test_listed_addresses_only(monkeypatch):
    monkeypatch.setattr(settings, "admin_allowed_ips", nets("203.0.113.0/28", "198.51.100.9", "2001:db8::/48"))
    for ip in ("203.0.113.1", "203.0.113.15", "198.51.100.9", "2001:db8::1", "::ffff:198.51.100.9"):
        assert deps.via_admin_channel(req(ip)), ip
    for ip in ("203.0.113.16", "198.51.100.10", "2001:db9::1", "10.214.0.10", "", "testclient", "not-an-ip"):
        assert not deps.via_admin_channel(req(ip)), ip


def test_setting_is_parsed_and_wrong_entries_stop_the_start(monkeypatch):
    monkeypatch.setenv("ADMIN_ALLOWED_IPS", " 203.0.113.7 , 10.1.2.0/24,2001:db8::/32 ")
    assert config._networks("ADMIN_ALLOWED_IPS") == nets("203.0.113.7/32", "10.1.2.0/24", "2001:db8::/32")
    monkeypatch.setenv("ADMIN_ALLOWED_IPS", "")
    assert config._networks("ADMIN_ALLOWED_IPS") == []
    for bad in ("203.0.113.300", "office", "10.0.0.0/33"):
        monkeypatch.setenv("ADMIN_ALLOWED_IPS", bad)
        with pytest.raises(RuntimeError, match="ADMIN_ALLOWED_IPS"):
            config._networks("ADMIN_ALLOWED_IPS")
