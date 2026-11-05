"""Browser manager: starts, restarts and removes one isolated browser container per user.

This is the only service with Docker access. The gateway can only ask for "the browser
of user N"; image, mounts, limits and security options are fixed here, so a compromised
gateway can't use this API to start arbitrary containers.
"""
import logging
import os
import secrets
import threading
import time

import docker
from docker.errors import APIError, NotFound
from docker.types import Mount
from fastapi import FastAPI, Header, HTTPException

log = logging.getLogger("browser-manager")
logging.basicConfig(level=logging.INFO)

TOKEN = os.environ["MANAGER_TOKEN"]
IMAGE = os.environ.get("BROWSER_IMAGE", "tgviewer-browser:latest")
FILES_VOLUME = os.environ.get("BROWSER_FILES_VOLUME", "tgviewer_browserfiles")
LAUNCH_URL = os.environ.get("BROWSER_LAUNCH_URL", "https://web.telegram.org/a/")
MEMORY = os.environ.get("BROWSER_MEMORY", "2g")
CPUS = float(os.environ.get("BROWSER_CPUS", "1.5"))
SUBNET_PREFIX = os.environ.get("BROWSER_SUBNET_PREFIX", "10.213")
CLIPBOARD_TO_PC = os.environ.get("BROWSER_CLIPBOARD_TO_PC", "false").lower() == "true"
CLIPBOARD_FROM_PC = os.environ.get("BROWSER_CLIPBOARD_FROM_PC", "true").lower() == "true"

client = docker.from_env()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _auth(token: str) -> None:
    if not secrets.compare_digest(token or "", TOKEN):
        raise HTTPException(401, "bad token")


def _names(uid: int) -> tuple[str, str, str]:
    return f"tgv-browser-u{uid}", f"tgv-net-u{uid}", f"tgv-profile-u{uid}"


def _service(role: str):
    found = client.containers.list(filters={"label": f"tgv.role={role}"})
    if not found:
        raise HTTPException(503, f"{role} container not found")
    return found[0]


def _network(uid: int):
    _, net_name, _ = _names(uid)
    try:
        net = client.networks.get(net_name)
    except NotFound:
        # One *internal* network per user: no route to the internet, the host, the LAN, other
        # users or the backend. The only ways out are the gateway (stream) and the egress proxy.
        ipam = docker.types.IPAMConfig(pool_configs=[
            docker.types.IPAMPool(subnet=f"{SUBNET_PREFIX}.{uid % 256}.0/24")])
        net = client.networks.create(net_name, driver="bridge", internal=True, ipam=ipam,
                                     labels={"tgv.managed": "1", "tgv.user": str(uid)})
    net.reload()
    attached = {c.id for c in net.containers}
    # The browser reaches the proxy by the name "egress" (Chromium policy); the gateway needs no name.
    for role, aliases in (("gateway", None), ("egress", ["egress"])):
        service = _service(role)
        if service.id not in attached:
            net.connect(service, aliases=aliases)
    return net


def _subpath_mount(target: str, subpath: str, read_only: bool = False) -> Mount:
    m = Mount(target, FILES_VOLUME, type="volume", read_only=read_only)
    m.setdefault("VolumeOptions", {})["Subpath"] = subpath
    return m


def _create(uid: int):
    name, net_name, profile = _names(uid)
    password = secrets.token_urlsafe(24)
    env = {
        "VNC_PW": password,
        "LAUNCH_URL": LAUNCH_URL,
        "VNC_RESOLUTION": "1600x900",
        # Everything except the screen stream is switched off.
        "KASM_SVC_UPLOADS": "0", "KASM_SVC_AUDIO": "0", "KASM_SVC_AUDIO_INPUT": "0",
        "KASM_SVC_GAMEPAD": "0", "KASM_SVC_WEBCAM": "0", "KASM_SVC_PRINTER": "0",
        "KASM_SVC_SMARTCARD": "0", "KASM_SVC_RECORDER": "0",
        "KASM_SVC_SEND_CUT_TEXT": f"-SendCutText={int(CLIPBOARD_TO_PC)}",
        "KASM_SVC_ACCEPT_CUT_TEXT": f"-AcceptCutText={int(CLIPBOARD_FROM_PC)}",
    }
    mounts = [
        Mount("/home/kasm-user", profile, type="volume"),  # persistent profile (Telegram Web login)
        _subpath_mount("/home/kasm-user/tgv-downloads", f"u{uid}/downloads"),
        # Empty and read-only: KasmVNC's built-in download page always has nothing to serve.
        _subpath_mount("/home/kasm-user/Downloads", "_empty", read_only=True),
        _subpath_mount("/home/kasm-user/Uploads", f"u{uid}/uploads", read_only=True),
        _subpath_mount("/etc/chromium/policies/managed", "_policy", read_only=True),
    ]
    return client.containers.create(
        IMAGE, name=name, hostname=name, environment=env, mounts=mounts,
        labels={"tgv.managed": "1", "tgv.user": str(uid), "tgv.vnc_password": password},
        network=net_name, shm_size="512m", mem_limit=MEMORY, nano_cpus=int(CPUS * 1e9),
        pids_limit=1024, security_opt=["no-new-privileges:true"],
        restart_policy={"Name": "unless-stopped"})


def _reconcile_forever() -> None:
    """Re-attach the gateway and egress proxy to every user network (they lose the attachment
    whenever their containers are recreated, e.g. on an update)."""
    while True:
        try:
            for net in client.networks.list(filters={"label": "tgv.managed=1"}):
                _network(int(net.attrs["Labels"]["tgv.user"]))
        except Exception:
            log.exception("network reconcile failed")
        time.sleep(20)


@app.on_event("startup")
def _start_reconciler() -> None:
    threading.Thread(target=_reconcile_forever, daemon=True).start()


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/browsers/{uid}/ensure")
def ensure(uid: int, x_manager_token: str = Header("")):
    _auth(x_manager_token)
    name, _, _ = _names(uid)
    _network(uid)
    try:
        c = client.containers.get(name)
    except NotFound:
        c = _create(uid)
        log.info("created browser for user %s", uid)
    if c.status != "running":
        c.start()
    return {"host": name, "port": 6901, "password": c.labels["tgv.vnc_password"]}


@app.post("/browsers/{uid}/restart")
def restart(uid: int, x_manager_token: str = Header("")):
    _auth(x_manager_token)
    try:
        client.containers.get(_names(uid)[0]).restart(timeout=10)
    except NotFound:
        raise HTTPException(404, "no browser")
    return {"ok": True}


@app.get("/browsers/{uid}")
def status(uid: int, x_manager_token: str = Header("")):
    _auth(x_manager_token)
    try:
        c = client.containers.get(_names(uid)[0])
        return {"exists": True, "status": c.status}
    except NotFound:
        return {"exists": False, "status": "none"}


@app.delete("/browsers/{uid}")
def destroy(uid: int, x_manager_token: str = Header("")):
    """Removes the container, the profile (Telegram Web login) and the network."""
    _auth(x_manager_token)
    name, net_name, profile = _names(uid)
    try:
        client.containers.get(name).remove(force=True)
    except NotFound:
        pass
    try:
        client.volumes.get(profile).remove(force=True)
    except NotFound:
        pass
    try:
        net = client.networks.get(net_name)
        for c in net.containers:
            net.disconnect(c, force=True)
        net.remove()
    except (NotFound, APIError):
        pass
    log.info("removed browser for user %s", uid)
    return {"ok": True}
