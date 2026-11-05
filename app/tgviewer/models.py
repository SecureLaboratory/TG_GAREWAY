"""Database tables.

Personal accounts: message text is never stored. Files and links are kept
only as long as the retention settings allow (see maintenance.py).
"""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _ts(**kw):
    return mapped_column(DateTime(timezone=True), **kw)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_secret_enc: Mapped[str] = mapped_column(Text)
    totp_last_step: Mapped[int] = mapped_column(BigInteger, default=0)
    # Role separation: admins manage users and statistics only; they can't use Telegram.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = _ts(nullable=True)
    consent_at: Mapped[datetime | None] = _ts(nullable=True)
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class WebSession(Base):
    __tablename__ = "web_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = _ts()


class PendingLogin(Base):
    """Password step passed, waiting for the authenticator code (or first-time enrollment)."""
    __tablename__ = "pending_logins"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = _ts()
    enroll_secret_enc: Mapped[str] = mapped_column(Text, default="")  # set only while enrolling
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    mfa_done: Mapped[bool] = mapped_column(Boolean, default=False)  # waiting only for a new password


class TgSession(Base):
    __tablename__ = "tg_sessions"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    session_enc: Mapped[str] = mapped_column(Text)
    phone_masked: Mapped[str] = mapped_column(String(32))
    linked_at: Mapped[datetime] = _ts(server_default=func.now())


class FileObj(Base):
    """One attachment: inbound (received, scanned on request) or outbound (being sent)."""
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    direction: Mapped[str] = mapped_column(String(8))
    chat_id: Mapped[int] = mapped_column(BigInteger)
    chat_kind: Mapped[str] = mapped_column(String(16), default="")
    msg_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    mime: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    # inbound: scanning | clean | suspicious | blocked | malicious | error | too_large | expired
    # outbound: scanning | sent | warn | dlp_blocked | suspicious | blocked | malicious | error
    status: Mapped[str] = mapped_column(String(16), default="scanning")
    reason: Mapped[str] = mapped_column(Text, default="")
    results: Mapped[list] = mapped_column(JSON, default=list)
    dlp_findings: Mapped[list] = mapped_column(JSON, default=list)
    q_path: Mapped[str] = mapped_column(Text, default="")
    clean_path: Mapped[str] = mapped_column(Text, default="")
    clean_mime: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    updated_at: Mapped[datetime] = _ts(server_default=func.now(), onupdate=func.now())

    __table_args__ = (Index("ix_files_user_chat_msg", "user_id", "chat_id", "msg_id"),)


class FileVerdict(Base):
    """Verdict cache, keyed by sha256 + extension (the type policy depends on the name)."""
    __tablename__ = "file_verdicts"
    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text, default="")
    mime: Mapped[str] = mapped_column(String(255), default="")
    results: Mapped[list] = mapped_column(JSON, default=list)
    scanned_at: Mapped[datetime] = _ts()


class Link(Base):
    """A link seen in a message, rewritten to /go/<id>. Kept for LINK_RETENTION_DAYS."""
    __tablename__ = "links"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255))
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text, default="")
    chat_ref: Mapped[str] = mapped_column(String(32), default="")
    chat_kind: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class ScanEvent(Base):
    """Metadata of every scan and link click; source of the statistics page."""
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = _ts(server_default=func.now(), index=True)
    object_type: Mapped[str] = mapped_column(String(8))      # file | url | click
    direction: Mapped[str] = mapped_column(String(8), default="inbound")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    chat_ref: Mapped[str] = mapped_column(String(32), default="")
    chat_kind: Mapped[str] = mapped_column(String(16), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    true_type: Mapped[str] = mapped_column(String(255), default="")
    ext: Mapped[str] = mapped_column(String(16), default="")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    domain: Mapped[str] = mapped_column(String(255), default="")
    url_hash: Mapped[str] = mapped_column(String(64), default="")
    full_url: Mapped[str] = mapped_column(Text, default="")  # only when not clean
    engine_results: Mapped[list] = mapped_column(JSON, default=list)
    flagged_engines: Mapped[list] = mapped_column(JSON, default=list)
    final_verdict: Mapped[str] = mapped_column(String(16), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    scan_ms: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(24), default="")
