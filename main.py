import base64
import ipaddress
import logging
import os
import re
import subprocess
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("wgctl")
logging.basicConfig(level=logging.INFO)

B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WGCTL_TOKEN = os.getenv("WGCTL_TOKEN", "")
if not WGCTL_TOKEN:
    raise RuntimeError("WGCTL_TOKEN is required")


def _validate_pubkey(pubkey: str) -> str:
    pk = pubkey.strip()
    if not B64_RE.match(pk):
        raise ValueError("invalid pubkey format")
    raw = base64.b64decode(pk + "=="[: (4 - len(pk) % 4) % 4], validate=True)
    if len(raw) != 32:
        raise ValueError("invalid pubkey length")
    return pk


def _validate_allowed_ips(allowed_ips: str) -> str:
    parts = [p.strip() for p in allowed_ips.split(",") if p.strip()]
    if not parts:
        raise ValueError("allowed_ips is empty")

    nets = []
    for p in parts:
        net = ipaddress.ip_network(p, strict=False)
        # Forbid full-tunnel in daemon to prevent accidental/malicious misuse
        if (net.version == 4 and net.prefixlen == 0) or (net.version == 6 and net.prefixlen == 0):
            raise ValueError("0.0.0.0/0 or ::/0 is forbidden")
        nets.append(str(net))
    return ",".join(nets)


def _run_wg(args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = ["wg", *args]
    logger.info("exec: %s", " ".join(cmd))
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _peer_exists(iface: str, pubkey: str) -> bool:
    r = _run_wg(["show", iface, "peers"])
    if r.returncode != 0:
        raise RuntimeError(f"wg show failed: {r.stderr.strip()}")
    return pubkey in set((r.stdout or "").split())


def _require_token(got: Optional[str]) -> None:
    if not got or got != WGCTL_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")


class AddPeerReq(BaseModel):
    pubkey: str = Field(..., min_length=10, max_length=128)
    allowed_ips: str = Field(..., min_length=3, max_length=256)
    endpoint: Optional[str] = Field(default=None, max_length=128)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)


class RemovePeerReq(BaseModel):
    pubkey: str = Field(..., min_length=10, max_length=128)


app = FastAPI(title="wgctl", version="0.1")


@app.get("/health")
def health():
    # Check if wg interface is up
    r = _run_wg(["show", WG_INTERFACE])
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"wg not ready: {r.stderr.strip()}")
    return {"ok": True, "iface": WG_INTERFACE}


@app.post("/peer/add")
def add_peer(req: AddPeerReq, x_wgctl_token: Optional[str] = Header(default=None)):
    _require_token(x_wgctl_token)
    try:
        pubkey = _validate_pubkey(req.pubkey)
        allowed_ips = _validate_allowed_ips(req.allowed_ips)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    args = ["set", WG_INTERFACE, "peer", pubkey, "allowed-ips", allowed_ips]

    if req.endpoint:
        ep = req.endpoint.strip()
        if ":" not in ep:
            raise HTTPException(status_code=400, detail="invalid endpoint")
        args += ["endpoint", ep]

    if req.persistent_keepalive is not None:
        args += ["persistent-keepalive", str(req.persistent_keepalive)]

    existed = _peer_exists(WG_INTERFACE, pubkey)

    r = _run_wg(args)
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"wg set failed: {r.stderr.strip()}")

    # Check if peer is now present
    if not _peer_exists(WG_INTERFACE, pubkey):
        raise HTTPException(status_code=500, detail="peer not present after wg set")

    return {"ok": True, "action": "update" if existed else "add", "pubkey": pubkey, "allowed_ips": allowed_ips}


@app.post("/peer/remove")
def remove_peer(req: RemovePeerReq, x_wgctl_token: Optional[str] = Header(default=None)):
    _require_token(x_wgctl_token)
    try:
        pubkey = _validate_pubkey(req.pubkey)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if not _peer_exists(WG_INTERFACE, pubkey):
        return {"ok": True, "action": "noop", "pubkey": pubkey}

    r = _run_wg(["set", WG_INTERFACE, "peer", pubkey, "remove"])
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"wg remove failed: {r.stderr.strip()}")

    if _peer_exists(WG_INTERFACE, pubkey):
        raise HTTPException(status_code=500, detail="peer still present after remove")

    return {"ok": True, "action": "remove", "pubkey": pubkey}
