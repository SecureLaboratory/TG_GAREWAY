"""Secrets from files (NAME_FILE, Docker secrets) win over environment variables."""
from tgviewer import config


def test_secret_file_wins_over_env(tmp_path, monkeypatch):
    f = tmp_path / "tg_api_hash"
    f.write_text("from-file\n")
    monkeypatch.setenv("TG_API_HASH", "from-env")
    monkeypatch.setenv("TG_API_HASH_FILE", str(f))
    assert config.secret("TG_API_HASH") == "from-file"
    monkeypatch.delenv("TG_API_HASH_FILE")
    assert config.secret("TG_API_HASH") == "from-env"


def test_database_password_from_file_is_put_into_url(tmp_path, monkeypatch):
    f = tmp_path / "pw"
    f.write_text("s3cr/t+pw")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://tgv:old@postgres:5432/tgv")
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(f))
    assert config._database_url() == "postgresql+asyncpg://tgv:s3cr%2Ft%2Bpw@postgres:5432/tgv"
