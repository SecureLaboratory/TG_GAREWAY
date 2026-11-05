"""Admin command line.

  python -m tgviewer.cli create-user alice [--admin]   (alice sets up her authenticator at first login)
  python -m tgviewer.cli set-password alice
  python -m tgviewer.cli reset-totp alice              (alice sets up a new authenticator at next login)
  python -m tgviewer.cli disable-user alice
  python -m tgviewer.cli list-users
  python -m tgviewer.cli scan-file /path/to/file
"""
import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path

from sqlalchemy import delete, select

from .db import SessionLocal, init_db
from .models import PendingLogin, User, WebSession
from .security import hash_password


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords don't match")
    if len(password) < 12:
        sys.exit("Use at least 12 characters")
    return password


async def _end_sessions(db, user_id: int) -> None:
    await db.execute(delete(WebSession).where(WebSession.user_id == user_id))
    await db.execute(delete(PendingLogin).where(PendingLogin.user_id == user_id))


async def _get_user(db, username: str) -> User:
    user = (await db.execute(select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if user is None:
        sys.exit(f"No such user: {username}")
    return user


async def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="tgviewer.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-user")
    p.add_argument("username")
    p.add_argument("--admin", action="store_true")
    p.add_argument("--password-stdin", action="store_true")
    p = sub.add_parser("set-password")
    p.add_argument("username")
    p.add_argument("--password-stdin", action="store_true")
    sub.add_parser("reset-totp").add_argument("username")
    sub.add_parser("disable-user").add_argument("username")
    sub.add_parser("list-users")
    p = sub.add_parser("scan-file")
    p.add_argument("path")
    p.add_argument("--name", help="file name to apply the type policy to (default: real name)")
    args = parser.parse_args(argv)

    await init_db()
    async with SessionLocal() as db:
        if args.cmd == "create-user":
            username = args.username.strip().lower()
            if (await db.execute(select(User).where(User.username == username))).scalar_one_or_none():
                sys.exit("User already exists")
            password = _read_password(args.password_stdin)
            db.add(User(username=username, password_hash=hash_password(password), totp_secret_enc="",
                        is_admin=args.admin))
            await db.commit()
            print(f"Created user {username}{' (admin)' if args.admin else ''}. "
                  "The authenticator app is set up in the browser at first login.")
        elif args.cmd == "set-password":
            user = await _get_user(db, args.username)
            user.password_hash = hash_password(_read_password(args.password_stdin))
            user.failed_logins, user.locked_until = 0, None
            await _end_sessions(db, user.id)
            await db.commit()
            print("Password updated; existing sessions ended.")
        elif args.cmd == "reset-totp":
            user = await _get_user(db, args.username)
            user.totp_secret_enc, user.totp_last_step = "", 0
            await _end_sessions(db, user.id)
            await db.commit()
            print(f"Authenticator removed for {user.username}; a new one is set up at next login.")
        elif args.cmd == "disable-user":
            from .telegram import tg
            user = await _get_user(db, args.username)
            user.disabled = True
            await _end_sessions(db, user.id)
            await db.commit()
            await tg.unlink(user.id)  # offboarding: also ends the Telegram session
            print(f"Disabled {user.username} and unlinked Telegram.")
        elif args.cmd == "list-users":
            for u in (await db.execute(select(User).order_by(User.id))).scalars():
                flags = [f for f, on in (("admin", u.is_admin), ("disabled", u.disabled),
                                         ("no-authenticator-yet", not u.totp_secret_enc)) if on]
                print(f"{u.id:4}  {u.username:24} {' '.join(flags)}")
        elif args.cmd == "scan-file":
            from .feeds import store
            from .scanning import pipeline
            await asyncio.to_thread(store.load_all)
            path = Path(args.path)
            res = await pipeline.scan_file(path, args.name or path.name, use_cache=False)
            print(json.dumps({"verdict": res.verdict, "reason": res.reason, "sha256": res.sha256,
                              "mime": res.mime, "ms": res.ms, "engines": res.results}, indent=2))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
