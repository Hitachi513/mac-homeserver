"""Security monitoring: every suspicious request becomes an event; events are counted per hour for the
security page, and an address that keeps guessing gets banned automatically.

Addresses come from the portal (Tailscale Funnel puts the real client address in X-Forwarded-For and overwrites
anything the client sends, verified by a live test) or from the panel (always a tailnet member)."""
import collections
import json
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EV_FILE = os.path.join(HERE, "security-events.json")
BAN_FILE = os.path.join(HERE, "security-bans.json")

# kind -> (label shown to the owner, severity)
KINDS = {
    "bad_token": ("猜錯成員網址", "warn"),
    "rate_limited": ("嘗試太多次被限速", "warn"),
    "banned_hit": ("被封鎖的位址又來了", "bad"),
    "auto_ban": ("自動封鎖", "bad"),
    "share_pw": ("分享密碼猜錯", "warn"),
    "share_bad": ("猜分享連結", "warn"),
    "csrf": ("擋下跨站請求", "bad"),
    "spoof": ("偽造身分連控制台", "bad"),
    "denied": ("沒有權限的人連控制台", "warn"),
    "lock_fail": ("控制台密碼輸錯", "warn"),
    "kick_pw": ("踢人密碼輸錯", "warn"),
    "oversize": ("擋下超大請求", "warn"),
    "backup_denied": ("沒開放的自動備份", "info"),
}
# how many events of these kinds from one address within an hour gets it banned for a day
BAN_RULES = {"bad_token": 40, "share_bad": 40, "share_pw": 25, "csrf": 10, "oversize": 10}
BAN_HOURS = 24
KEEP_DAYS = 7

_lock = threading.Lock()
_events = collections.deque(maxlen=2000)
_bans = {}
_dirty = {"ev": False, "ban": False, "at": 0}
_exempt = set()        # addresses never banned (our own public IP: every Shadowrocket member shares it)
_on_ban = None         # callback(ip, reason) → push notification


def configure(exempt=(), on_ban=None):
    global _on_ban
    _exempt.update(x for x in exempt if x)
    if on_ban:
        _on_ban = on_ban


def _load():
    try:
        with open(EV_FILE) as f:
            cut = time.time() - KEEP_DAYS * 86400
            _events.extend(e for e in json.load(f) if e.get("t", 0) > cut)
    except (OSError, ValueError):
        pass
    try:
        with open(BAN_FILE) as f:
            _bans.update(json.load(f))
    except (OSError, ValueError):
        pass


def _write(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def flush(force=False):
    with _lock:
        if not force and time.time() - _dirty["at"] < 30:
            return
        if _dirty["ev"]:
            _write(EV_FILE, list(_events))
        if _dirty["ban"]:
            _write(BAN_FILE, _bans)
        _dirty.update(ev=False, ban=False, at=time.time())


def record(kind, ip=None, detail="", who=None):
    """Log one suspicious event. Self-test traffic (X-Forwarded-For: selftest-…) is ignored."""
    if ip and str(ip).startswith("selftest"):
        return
    now = time.time()
    ev = {"t": now, "kind": kind, "ip": ip, "detail": str(detail)[:200], "who": who}
    banned = None
    with _lock:
        _events.append(ev)
        _dirty["ev"] = True
        lim = BAN_RULES.get(kind)
        if lim and ip and ip not in _exempt and not is_banned(ip, _locked=True):
            n = sum(1 for e in _events if e["ip"] == ip and e["kind"] == kind and now - e["t"] < 3600)
            if n >= lim:
                _bans[ip] = {"at": now, "until": now + BAN_HOURS * 3600, "reason": f"一小時內 {n} 次「{KINDS[kind][0]}」"}
                _dirty["ban"] = True
                banned = _bans[ip]["reason"]
                _events.append({"t": now, "kind": "auto_ban", "ip": ip, "detail": banned, "who": None})
    if banned and _on_ban:
        try:
            _on_ban(ip, banned)
        except Exception:
            pass
    flush()


def is_banned(ip, _locked=False):
    b = _bans.get(ip)
    if not b:
        return False
    if b["until"] < time.time():
        if not _locked:
            with _lock:
                _bans.pop(ip, None)
                _dirty["ban"] = True
        return False
    return True


def ban(ip, hours=BAN_HOURS, reason="手動封鎖"):
    with _lock:
        _bans[ip] = {"at": time.time(), "until": time.time() + hours * 3600, "reason": reason}
        _dirty["ban"] = True
    flush(True)


def unban(ip):
    with _lock:
        _bans.pop(ip, None)
        _dirty["ban"] = True
    flush(True)


def summary(hours=24):
    now = time.time()
    start = int(now // 3600 - hours + 1) * 3600
    with _lock:
        evs = [e for e in _events if e["t"] >= start]
        bans = {ip: b for ip, b in _bans.items() if b["until"] > now}
    hourly = [{"t": start + i * 3600, "n": 0, "bad": 0} for i in range(hours)]
    by_kind = collections.Counter()
    by_ip = collections.Counter()
    for e in evs:
        i = int((e["t"] - start) // 3600)
        if 0 <= i < hours:
            hourly[i]["n"] += 1
            if KINDS.get(e["kind"], ("", "warn"))[1] == "bad":
                hourly[i]["bad"] += 1
        by_kind[e["kind"]] += 1
        if e["ip"]:
            by_ip[e["ip"]] += 1
    recent = sorted(evs, key=lambda e: -e["t"])[:60]
    return {"hourly": hourly, "total": len(evs), "by_kind": dict(by_kind), "top_ips": by_ip.most_common(8),
            "recent": recent, "bans": [{"ip": ip, **b} for ip, b in sorted(bans.items(), key=lambda x: -x[1]["at"])],
            "kinds": {k: {"label": v[0], "level": v[1]} for k, v in KINDS.items()}, "rules": BAN_RULES, "ban_hours": BAN_HOURS}


_load()
