"""Windows PCs the owner controls from the panel.

A small PowerShell agent on the PC keeps one request open to the panel (/agent/sync, through Tailscale) and
gets commands back as answers, so the PC needs no open port or firewall rule. Pairing uses a one-time code
shown in the owner's panel; after that the agent proves itself with a random token (only its hash is kept here)
and must keep coming from the same Tailscale account it paired from. The agent only runs the fixed commands
in COMMANDS, never anything sent as code.
"""
import hashlib
import json
import os
import secrets
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "winagents.json")
SCRIPT_DIR = os.path.join(HERE, "winagent")
AGENT_VER = "1"
CODE_TTL = 15 * 60
ONLINE_S = 45      # the agent checks in at least every ~25 s
WAIT_IDLE = 25     # how long a sync is held open when nobody is looking
WAIT_WATCHED = 3   # ...and while someone has the PC open in the panel (fresh stats)
COMMANDS = {
    "media": "音樂控制", "volume": "設定音量", "mute": "切換靜音", "notify": "跳出通知", "say": "念出文字",
    "open_url": "開網址", "lock": "鎖定", "display_off": "關螢幕", "sleep": "睡眠",
    "shutdown": "關機", "restart": "重新開機", "cancel_shutdown": "取消關機", "screenshot": "擷取畫面",
    "clipboard_get": "讀取剪貼簿", "clipboard_set": "設定剪貼簿", "uninstall": "移除遙控程式",
}

_cv = threading.Condition()
_codes = {}      # code -> expires
_queue = {}      # agent id -> [cmd]
_results = {}    # cmd id -> result
_watch = {}      # agent id -> watched until
_fails = {"n": 0, "t": 0}


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _load():
    try:
        with open(FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    d.setdefault("agents", {})
    d.setdefault("revoked", [])
    return d


def _save(d):
    os.makedirs(os.path.dirname(FILE), exist_ok=True)
    fd = os.open(FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(FILE + ".tmp", FILE)


_db = _load()
_live = {}  # agent id -> {"seen": t, "stats": {...}, "ver": str} (kept in memory; stats change every few seconds)


def new_code():
    with _cv:
        now = time.time()
        for c in [c for c, exp in _codes.items() if exp < now]:
            del _codes[c]
        code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        _codes[code] = now + CODE_TTL
        return {"code": code, "expires": _codes[code]}


def code_ok(code):
    """True when `code` is a live pairing code. Repeated wrong codes wipe all codes (someone guessing)."""
    with _cv:
        if _codes.get(str(code or "").upper(), 0) > time.time():
            return True
        now = time.time()
        if now - _fails["t"] > 3600:
            _fails["n"] = 0
        _fails["n"] += 1
        _fails["t"] = now
        if _fails["n"] >= 10:
            _codes.clear()
        return False


def pair(code, name, login):
    """Use up a pairing code; returns (agent id, token)."""
    with _cv:
        code = str(code or "").upper()
        if _codes.get(code, 0) <= time.time():
            raise PermissionError("配對碼錯誤或已過期，請在控制台重新產生")
        del _codes[code]
        aid = secrets.token_hex(6)
        token = secrets.token_urlsafe(32)
        _db["agents"][aid] = {"name": (str(name or "").strip() or "Windows 電腦")[:40], "login": login,
                              "hash": _h(token), "created": time.time()}
        _save(_db)
        return aid, token


def auth(token, login):
    """Agent id for this token, "revoked" for a removed PC, or None."""
    if not token:
        return None
    h = _h(token)
    for aid, a in _db["agents"].items():
        if secrets.compare_digest(a["hash"], h):
            return aid if a["login"] == login else None
    return "revoked" if h in _db["revoked"] else None


def sync(aid, body):
    """One check-in: store stats and results, then hold the request until there is work (or a timeout)."""
    with _cv:
        _live[aid] = {"seen": time.time(), "stats": body.get("stats") or {}, "ver": str(body.get("ver") or "")}
        for r in body.get("results") or []:
            if isinstance(r, dict) and r.get("id"):
                _results[str(r["id"])] = r
                if len(_results) > 50:
                    _results.pop(next(iter(_results)))
        _cv.notify_all()
        if _live[aid]["ver"] != AGENT_VER:
            return {"update": True}
        t0 = time.time()

        def ready():  # work to do, or someone is looking at this PC and wants fresh numbers
            if _queue.get(aid) or aid not in _db["agents"]:
                return True
            return _watch.get(aid, 0) > time.time() and time.time() - t0 >= WAIT_WATCHED
        while not ready() and time.time() - t0 < WAIT_IDLE:
            _cv.wait(1)
        if aid not in _db["agents"]:
            return {"revoked": True}
        cmds, _queue[aid] = _queue.get(aid) or [], []
        _live[aid]["seen"] = time.time()
        return {"cmds": cmds}


def send(aid, name, arg, timeout=20):
    """Queue a command and wait for the PC's answer."""
    if name not in COMMANDS:
        return {"ok": False, "error": "不支援的指令"}
    with _cv:
        if aid not in _db["agents"]:
            return {"ok": False, "error": "找不到這台電腦"}
        if not online(aid):
            return {"ok": False, "error": "這台電腦沒有連線（關機、睡眠、沒開 Tailscale，或遙控程式沒在跑）"}
        cid = secrets.token_hex(6)
        _queue.setdefault(aid, []).append({"id": cid, "name": name, "arg": arg or {}})
        _watch[aid] = time.time() + 30
        _cv.notify_all()
        if not _cv.wait_for(lambda: cid in _results, timeout=timeout):
            _queue[aid] = [c for c in _queue.get(aid, []) if c["id"] != cid]
            return {"ok": False, "error": "電腦沒有回應，可能剛好斷線"}
        r = _results.pop(cid)
        return {"ok": bool(r.get("ok")), "error": str(r.get("error") or "")[:300], **(r.get("data") or {})}


def online(aid):
    return time.time() - (_live.get(aid) or {}).get("seen", 0) < ONLINE_S


def listing(watch=True):
    now = time.time()
    with _cv:
        out = []
        for aid, a in sorted(_db["agents"].items(), key=lambda x: x[1]["created"]):
            if watch:
                _watch[aid] = now + 20
            lv = _live.get(aid) or {}
            out.append({"id": aid, "name": a["name"], "login": a["login"], "created": a["created"],
                        "online": online(aid), "seen": lv.get("seen") or a.get("seen"), "stats": lv.get("stats") or {}})
        _cv.notify_all()  # wake idle agents so the stats are fresh
        return out


def rename(aid, name):
    with _cv:
        if aid not in _db["agents"]:
            raise KeyError("找不到這台電腦")
        _db["agents"][aid]["name"] = str(name or "").strip()[:40] or _db["agents"][aid]["name"]
        _save(_db)


def remove(aid):
    """Forget a PC; if it checks in again it is told to uninstall itself."""
    with _cv:
        a = _db["agents"].pop(aid, None)
        if not a:
            raise KeyError("找不到這台電腦")
        _db["revoked"] = (_db["revoked"] + [a["hash"]])[-50:]
        _save(_db)
        _live.pop(aid, None)
        _cv.notify_all()
        return a["name"]


def name_of(aid):
    return (_db["agents"].get(aid) or {}).get("name", aid)


def script(kind, **values):
    """install.ps1 / agent.ps1 with placeholders filled. agent.ps1 is saved to disk, so it gets a UTF-8 BOM:
    Windows PowerShell 5.1 reads a .ps1 without one in the local code page, which garbles the Chinese text.
    install.ps1 is piped into `iex` as a string (decoded by the charset header), where a BOM would break it."""
    with open(os.path.join(SCRIPT_DIR, kind + ".ps1"), encoding="utf-8") as f:
        text = f.read().replace("__VER__", AGENT_VER)
    for k, v in values.items():
        text = text.replace(f"__{k.upper()}__", v)
    return ("\ufeff" if kind == "agent" else "") + text
