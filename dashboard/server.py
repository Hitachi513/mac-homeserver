#!/usr/bin/env python3
"""Home control panel: a small stdlib-only backend for the Tailscale-served dashboard.

Listens on 127.0.0.1 only; it is reached through `tailscale serve`, which injects the
Tailscale-User-Login header. Every /api request must carry that header, so a random web
page in a local browser can't drive these endpoints (browsers can't set it cross-origin).
"""
import base64
import collections
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import uuid as uuidlib

import applock
import drive
import notify
import macstats
import security
import settings
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_JSON = 1 << 20  # JSON bodies are tiny; refuse anything claiming more instead of waiting to read it


class BoundedServer(ThreadingHTTPServer):
    """At most `limit` requests at once: a flood of slow connections can't exhaust threads/memory."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, addr, handler, limit=96):
        self._slots = threading.BoundedSemaphore(limit)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class TooLarge(Exception):
    pass

HOST, PORT = "127.0.0.1", 8088
HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
TAILSCALE = shutil.which("tailscale") or "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
AGH_URL = "http://127.0.0.1:3000/control/"
AGH_LABEL = settings.LABEL_PREFIX + ".adguardhome"
# Not in ~/Downloads: macOS privacy protection blocks launchd agents there (a symlink in Downloads points here)
BOX_DIR = os.path.join(HOME, "homeserver", "傳輸箱")
CRED_FILE = os.path.join(HOME, "homeserver", "credentials.txt")
# Only these Tailscale identities may use the panel, even if other people join the tailnet.
OWNERS = settings.OWNERS  # from ~/homeserver/config.json
MAX_UPLOAD = 4 << 30  # 4 GB
SECRETS_FILE = os.path.join(HERE, "secrets.json")  # kick password hash + Tailscale OAuth client, mode 600
TS_API = "https://api.tailscale.com/api/v2"
# ---- Shadowrocket: Xray VLESS over WebSocket on 127.0.0.1:10080, published by the user with Tailscale Funnel :8443
XRAY_BIN = "/opt/homebrew/bin/xray"
XRAY_DIR = os.path.join(HOME, "homeserver", "xray")
XRAY_CONFIG = os.path.join(XRAY_DIR, "config.json")
XRAY_USAGE = os.path.join(XRAY_DIR, "usage.json")
XRAY_LABEL = settings.LABEL_PREFIX + ".xray"
XRAY_API = "127.0.0.1:10085"
PROXY_PORT = 8443
# ---- Member portal: read-only page per person, published under /p on the same Funnel port (8443)
PORTAL_HOST, PORTAL_PORT = "127.0.0.1", 8090
PORTAL_PREFIX = "/p"
# AdGuard blocked-service id -> Xray geosite list (only lists that exist in the bundled geosite.dat)
SR_GEOSITE = {"youtube": "youtube", "tiktok": "tiktok", "facebook": "facebook", "instagram": "instagram",
              "twitter": "twitter", "discord": "discord", "twitch": "twitch", "netflix": "netflix", "roblox": "roblox",
              "steam": "steam", "epic_games": "epicgames", "leagueoflegends": "riot", "snapchat": "snap", "reddit": "reddit",
              "threads": "threads", "chatgpt": "openai", "shopee": "shopee", "spotify": "spotify", "disneyplus": "disney",
              "pinterest": "pinterest", "line": "line", "telegram": "telegram", "whatsapp": "whatsapp"}
PERMS_FILE = os.path.join(HERE, "members.json")  # per-person permissions; source of truth for the ACL we generate
# Services on this Mac a member can be granted: key -> (label, ports reached through the tailnet)
MAC_SERVICES = {
    "dns": ("擋廣告 DNS", ["tcp:53", "udp:53"]),
    "remote": ("網頁遠端桌面", ["tcp:6443", "tcp:5900"]),
    "files": ("檔案共享 (SMB)", ["tcp:445"]),
    "panel": ("控制台", ["tcp:443"]),
    "agh": ("AdGuard 管理介面", ["tcp:3443"]),
}
# What a non-owner may do inside the panel
PANEL_CAPS = {
    "view": "看總覽、裝置、系統狀態",
    "log": "看自己裝置的上網紀錄",
    "adblock": "調整擋廣告（全家共用設定）",
    "remote": "遙控 Mac（音樂、音量、通知、開網址）",
    "screen": "看 Mac 螢幕、讀寫剪貼簿",
}
ACTION_CAPS = {
    "notify": "remote", "say": "remote", "volume": "remote", "mute": "remote", "media": "remote",
    "display_sleep": "remote", "open_url": "remote", "keep_awake": "remote",
    "screenshot": "screen", "clipboard_get": "screen", "clipboard_set": "screen",
    "ts_ping": "view", "netcheck": "view",
    "agh_protection": "adblock", "agh_rule": "adblock", "agh_cache_clear": "adblock", "agh_refresh": "adblock",
    "agh_filter_toggle": "adblock", "agh_services_set": "adblock",
}  # anything not listed is owner-only
FILTER_OPTS = {"ads": "擋廣告", "adult": "擋成人網站", "safesearch": "強制安全搜尋", "malware": "擋危險網站"}
WEEKDAYS = "一二三四五六日"
# ACL sections the panel rewrites; everything else in the live policy is preserved
MANAGED_KEYS = {"acls", "grants", "hosts", "tests"}
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data: https://avatars.githubusercontent.com https://*.googleusercontent.com; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}

# Core services: (key, port, name, kind). kind: "sharing" needs a System Settings toggle;
# "web" gets an https link through tailscale serve (see SERVE_PORTS); "dns" has no link.
CORE = [
    ("dns", 53, "AdGuard DNS（擋廣告）", "dns"),
    ("agh", 3000, "AdGuard 管理介面", "web"),
    ("panel", 8088, "家用控制台（這個頁面）", "web"),
    ("novnc", 6080, "網頁版遠端桌面 (noVNC)", "web"),
    ("ssh", 22, "SSH 遠端登入", "sharing"),
    ("vnc", 5900, "螢幕共享 (VNC)", "sharing"),
    ("smb", 445, "檔案共享 (SMB)", "sharing"),
]
# local port -> tailnet https port it is served on
SERVE_PORTS = {3000: 3443, 8088: 443, 6080: 6443}
SHARING_HELP = {
    "ssh": "系統設定 → 一般 → 共享 → 打開「遠端登入」。手機用 Termius 之類的 SSH App 連。",
    "vnc": "系統設定 → 一般 → 共享 → 打開「螢幕共享」。手機用 RealVNC Viewer 之類的 VNC App 連。",
    "smb": "系統設定 → 一般 → 共享 → 打開「檔案分享」。iPhone「檔案」App → 右上 ⋯ → 連接伺服器。",
}
# Listening processes that are system/app noise, not services worth showing
NOISE = {"rapportd", "ControlCe", "ControlCenter", "Spotify", "AdGuardHo", "AdGuardHome", "Tailscale", "tailscaled",
         "IPNExtension", "io.tailscale.ipn.macsys.network-extension", "identityservicesd", "sharingd", "launchd", "mDNSResponder"}

EVENTS = collections.deque(maxlen=100)
_caffeinate = None
_cache = {}


def log_event(who, text):
    EVENTS.appendleft({"t": time.time(), "who": who, "text": text})


def run(cmd, timeout=10, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def cached(key, ttl, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


# ---------- AdGuard Home ----------

def agh_auth():
    try:
        with open(CRED_FILE) as f:
            line = next(l for l in f if l.startswith("AdGuard"))
        user, pw = line.split()[-3], line.split()[-1]
        return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    except (OSError, StopIteration, IndexError):
        return None


def agh(path, method="GET", body=None, timeout=10):
    req = urllib.request.Request(AGH_URL + path, method=method)
    auth = agh_auth()
    if auth:
        req.add_header("Authorization", auth)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        raw = r.read()
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {"text": raw.decode(errors="replace")}


def agh_overview():
    try:
        status = agh("status")
        stats = agh("stats")
        filt = agh("filtering/status")
    except Exception as e:  # service down or unreachable
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "protection": status.get("protection_enabled"),
        "protection_disabled_until": status.get("protection_disabled_until"),
        "version": status.get("version"),
        "queries": stats.get("num_dns_queries", 0),
        "blocked": stats.get("num_blocked_filtering", 0),
        "avg_ms": round(stats.get("avg_processing_time", 0) * 1000, 1),
        "hourly_total": stats.get("dns_queries", []),
        "hourly_blocked": stats.get("blocked_filtering", []),
        "top_queried": stats.get("top_queried_domains", [])[:10],
        "top_blocked": stats.get("top_blocked_domains", [])[:10],
        "top_clients": stats.get("top_clients", [])[:10],
        "filters": [{"id": f["id"], "name": f["name"], "enabled": f["enabled"], "rules": f.get("rules_count", 0),
                     "updated": f.get("last_updated")} for f in filt.get("filters") or []],
        "user_rules": filt.get("user_rules") or [],
    }


# ---------- Tailscale ----------

def ts_status():
    code, out, err = run([TAILSCALE, "status", "--json"])
    if code != 0:
        return {"ok": False, "error": err.strip() or "tailscale status failed"}
    d = json.loads(out)

    def node(n, is_self=False):
        return {
            "id": n.get("ID"),
            "name": ((n.get("DNSName") or "").split(".")[0] if n.get("HostName") in (None, "", "localhost") else n.get("HostName")),
            "dns": (n.get("DNSName") or "").rstrip("."),
            "os": n.get("OS"),
            "ips": n.get("TailscaleIPs") or [],
            "online": True if is_self else n.get("Online"),
            "self": is_self,
            "last_seen": n.get("LastSeen"),
            "rx": n.get("RxBytes", 0),
            "tx": n.get("TxBytes", 0),
            "direct": bool(n.get("CurAddr")),
            "relay": n.get("Relay"),
            "cur_addr": n.get("CurAddr"),
            "exit_node": n.get("ExitNode"),
            "exit_option": n.get("ExitNodeOption"),
            "offers_exit": "0.0.0.0/0" in (n.get("AllowedIPs") or []) or "0.0.0.0/0" in (n.get("PrimaryRoutes") or []),
        }

    # Funnel relays show up as shared-in peers; they are Tailscale's servers, not devices
    peers = [node(p) for p in (d.get("Peer") or {}).values()
             if not p.get("ShareeNode") and p.get("HostName") != "funnel-ingress-node"]
    peers.sort(key=lambda p: (not p["online"], p["name"] or ""))
    return {
        "ok": True,
        "backend": d.get("BackendState"),
        "tailnet": (d.get("CurrentTailnet") or {}).get("Name"),
        "magic_dns_suffix": (d.get("CurrentTailnet") or {}).get("MagicDNSSuffix"),
        "https": bool(d.get("CertDomains")),
        "self": node(d["Self"], True),
        "peers": peers,
    }


def ts_netcheck():
    code, out, err = run([TAILSCALE, "netcheck", "--format=json"], timeout=20)
    if code != 0:
        return {"ok": False, "error": err.strip()}
    d = json.loads(out)
    lat = sorted(((k, v / 1e6) for k, v in (d.get("RegionLatency") or {}).items()), key=lambda x: x[1])
    # Region ids are numeric; map the common ones to readable names.
    names = {"1": "紐約", "2": "舊金山", "3": "新加坡", "4": "法蘭克福", "5": "雪梨", "6": "班加羅爾", "7": "東京",
             "8": "倫敦", "9": "達拉斯", "10": "西雅圖", "11": "聖保羅", "12": "芝加哥", "13": "丹佛", "14": "阿姆斯特丹",
             "15": "約翰尼斯堡", "16": "邁阿密", "17": "洛杉磯", "18": "巴黎", "19": "馬德里", "20": "香港",
             "21": "多倫多", "22": "華沙", "23": "杜拜", "24": "檀香山", "25": "奈洛比", "26": "那格浦爾"}
    return {
        "ok": True,
        "udp": d.get("UDP"),
        "ipv4": d.get("GlobalV4"),
        "ipv6": d.get("GlobalV6"),
        "nearest": names.get(str(d.get("PreferredDERP")), str(d.get("PreferredDERP"))),
        "latency": [{"region": names.get(k, k), "ms": round(v, 1)} for k, v in lat[:8]],
    }


# ---------- System ----------

def sysctl(name):
    return run(["sysctl", "-n", name])[1].strip()


def system_info():
    ncpu = int(sysctl("hw.ncpu") or 1)
    load = [float(x) for x in sysctl("vm.loadavg").strip("{} ").split()[:3]]
    boot = int(re.search(r"sec = (\d+)", sysctl("kern.boottime")).group(1))
    total_mem = int(sysctl("hw.memsize"))
    vm = run(["vm_stat"])[1]
    page = int(re.search(r"page size of (\d+)", vm).group(1))
    pages = {k.strip(): int(v.strip(" .")) for k, v in re.findall(r"^(.+?):\s+(\d+)\.?$", vm, re.M)}
    used = (pages.get("Pages active", 0) + pages.get("Pages wired down", 0)
            + pages.get("Pages occupied by compressor", 0)) * page
    du = shutil.disk_usage("/System/Volumes/Data" if os.path.exists("/System/Volumes/Data") else "/")
    batt = run(["pmset", "-g", "batt"])[1]
    m = re.search(r"(\d+)%;\s*([^;]+);", batt)
    ps = run(["ps", "-Aceo", "pid=,pcpu=,pmem=,comm="])[1]
    procs = []
    for line in ps.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            procs.append({"pid": int(parts[0]), "cpu": float(parts[1]), "mem": float(parts[2]), "name": parts[3]})
    cpu_total = sum(p["cpu"] for p in procs) / ncpu
    procs.sort(key=lambda p: p["cpu"], reverse=True)
    pm = run(["pmset", "-g"])[1]
    ac_sleep = re.search(r"^\s*sleep\s+(\d+)", pm, re.M)
    return {
        "hostname": socket.gethostname(),
        "os": run(["sw_vers", "-productVersion"])[1].strip(),
        "model": sysctl("hw.model"),
        "chip": sysctl("machdep.cpu.brand_string"),
        "ncpu": ncpu,
        "cpu_pct": round(min(cpu_total, 100), 1),
        "load": load,
        "uptime_s": int(time.time()) - boot,
        "mem_total": total_mem,
        "mem_used": used,
        "disk_total": du.total,
        "disk_used": du.total - du.free,
        "battery": int(m.group(1)) if m else None,
        "battery_state": m.group(2).strip() if m else None,
        "on_ac": "AC Power" in batt,
        "sleep_setting": int(ac_sleep.group(1)) if ac_sleep else None,
        "keep_awake": _caffeinate is not None and _caffeinate.poll() is None,
        "top_procs": procs[:8],
        "public_ip": cached("pubip", 300, public_ip),
    }


def public_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            return r.read().decode().strip()
    except Exception:
        return None


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def listening():
    """Map port -> {proc, pid, addrs} for TCP listeners owned by this user."""
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-u", str(os.getuid()), "-F", "pcn"])[1]
    res, pid, cmd = {}, None, None
    for line in out.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid = int(val)
        elif tag == "c":
            cmd = val
        elif tag == "n" and ":" in val:
            host, port = val.rsplit(":", 1)
            if port.isdigit():
                e = res.setdefault(int(port), {"proc": cmd, "pid": pid, "addrs": set()})
                e["addrs"].add(host.strip("[]"))
    return res


def services():
    ts_dns = cached("tsdns", 60, lambda: (json.loads(run([TAILSCALE, "status", "--json"])[1] or "{}").get("Self") or {}).get("DNSName", "").rstrip("."))
    core = []
    for key, port, name, kind in CORE:
        up = port_open(port)
        item = {"key": key, "port": port, "name": name, "kind": kind, "up": up, "link": None, "help": None}
        if kind == "web" and up and port in SERVE_PORTS and ts_dns:
            hp = SERVE_PORTS[port]
            item["link"] = f"https://{ts_dns}" + ("" if hp == 443 else f":{hp}")
            if key == "novnc":
                item["link"] += "/vnc.html?autoconnect=true&resize=scale&reconnect=true&show_dot=true&path=websockify"
        if kind == "sharing":
            item["help"] = SHARING_HELP[key]
            if up:
                item["link"] = {"ssh": "ssh://", "vnc": "vnc://", "smb": "smb://"}[key] + (ts_dns or "")
        core.append(item)
    known = {c[1] for c in CORE}
    others = []
    for port, e in sorted(listening().items()):
        if port in known or e["proc"] in NOISE or port >= 49152:
            continue
        local_only = all(a in ("127.0.0.1", "::1", "localhost") for a in e["addrs"])
        cwd = run(["lsof", "-a", "-p", str(e["pid"]), "-d", "cwd", "-Fn"])[1]
        cwd = next((l[1:] for l in cwd.splitlines() if l.startswith("n")), "")
        others.append({"port": port, "proc": e["proc"], "pid": e["pid"], "local_only": local_only,
                       "cwd": cwd.replace(HOME, "~"), "trashed": "/.Trash/" in cwd,
                       "link": None if local_only or not ts_dns else f"http://{ts_dns}:{port}"})
    code, o, _ = run(["launchctl", "print", f"gui/{os.getuid()}/{AGH_LABEL}"])
    pid = re.search(r"\bpid = (\d+)", o)
    return {"core": core, "others": others, "agh_agent": {"loaded": code == 0, "pid": int(pid.group(1)) if pid else None}}


# ---------- Mac remote actions ----------

def osa(script, timeout=8):
    return run(["osascript", "-e", script], timeout=timeout)


def osa_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def media_now():
    for app in ("Spotify", "Music"):
        if run(["pgrep", "-x", app])[0] != 0:
            continue
        code, out, _ = osa(f'with timeout of 3 seconds\ntell application "{app}" to if player state is playing or player state is paused then '
                           f'return (player state as text) & "␟" & name of current track & "␟" & artist of current track\nend timeout', timeout=5)
        if code == 0 and out.strip():
            state, name, artist = (out.strip().split("␟") + ["", "", ""])[:3]
            return {"app": app, "state": state, "track": name, "artist": artist}
        return {"app": app, "state": "stopped", "track": "", "artist": ""}
    return None


def get_volume():
    code, out, _ = osa("set v to get volume settings\nreturn ((output volume of v) as text) & \",\" & ((output muted of v) as text)")
    if code != 0:
        return None
    v, muted = out.strip().split(",")
    return {"level": int(v) if v.isdigit() else None, "muted": muted.strip() == "true"}


_media_state = {"media": None, "volume": None}


def media_poller():
    while True:
        _media_state["media"] = safe(media_now)
        _media_state["volume"] = safe(get_volume)
        time.sleep(4)


def action(name, arg, who):
    global _caffeinate
    if name == "notify":
        text = str(arg.get("text", ""))[:200]
        code, _, err = osa(f'display notification {osa_str(text)} with title "📱 來自手機" sound name "Glass"')
        log_event(who, f"傳通知到 Mac：{text}")
        return {"ok": code == 0, "error": err.strip()}
    if name == "say":
        text = str(arg.get("text", ""))[:300]
        subprocess.Popen(["say", text])
        log_event(who, f"讓 Mac 說話：{text}")
        return {"ok": True}
    if name == "clipboard_get":
        return {"ok": True, "text": run(["pbpaste"])[1][:20000]}
    if name == "clipboard_set":
        text = str(arg.get("text", ""))
        code, _, err = run(["pbcopy"], input_text=text)
        log_event(who, f"設定 Mac 剪貼簿（{len(text)} 字）")
        return {"ok": code == 0, "error": err}
    if name == "volume":
        lvl = max(0, min(100, int(arg.get("level", 50))))
        code, _, err = osa(f"set volume output volume {lvl} without output muted")
        log_event(who, f"音量設為 {lvl}")
        return {"ok": code == 0, "error": err.strip()}
    if name == "mute":
        code, _, err = osa("set volume with output muted")
        log_event(who, "Mac 靜音")
        return {"ok": code == 0, "error": err.strip()}
    if name == "media":
        cmd = {"playpause": "playpause", "next": "next track", "prev": "previous track"}.get(arg.get("cmd"))
        now = media_now()
        if not cmd or not now:
            return {"ok": False, "error": "沒有 Spotify / 音樂 App 在執行"}
        code, _, err = osa(f'tell application "{now["app"]}" to {cmd}')
        log_event(who, f"{now['app']}：{arg.get('cmd')}")
        return {"ok": code == 0, "error": err.strip()}
    if name == "kick_device":
        err = check_kick_pw(arg.get("password"), who)
        if err:
            return {"ok": False, "error": err}
        st = ts_status()
        target = next((p for p in st.get("peers", []) if p["id"] == arg.get("id")), None)
        if not target:
            return {"ok": False, "error": "找不到這台裝置（不能踢這台 Mac 自己）"}
        ts_api("DELETE", f"/device/{target['id']}")
        log_event(who, f"🥾 踢出裝置：{target['name']}（{', '.join(target['ips'][:1])}）")
        return {"ok": True}
    if name == "kick_setup":
        sec = load_secrets()
        if sec.get("kick_pw"):
            err = check_kick_pw(arg.get("password"), who)
            if err:
                return {"ok": False, "error": err}
        new_pw = arg.get("new_password")
        if new_pw:
            if len(new_pw) < 8:
                return {"ok": False, "error": "新密碼至少 8 個字"}
            sec["kick_pw"] = hash_pw(new_pw)
        if arg.get("api_key"):
            key = arg["api_key"].strip()
            if not key.startswith("tskey-api-"):
                return {"ok": False, "error": "API token 應該是 tskey-api- 開頭"}
            old_key, old_at = sec.get("ts_api_key"), sec.get("ts_api_key_saved")
            sec["ts_api_key"], sec["ts_api_key_saved"] = key, time.time()
            save_secrets(sec)
            try:
                ts_api("GET", "/tailnet/-/devices")
            except Exception as e:
                sec["ts_api_key"], sec["ts_api_key_saved"] = old_key, old_at
                if not old_key:
                    sec.pop("ts_api_key"); sec.pop("ts_api_key_saved")
                save_secrets(sec)
                return {"ok": False, "error": f"API token 驗證失敗：{e}"}
        if arg.get("client_id") and arg.get("client_secret"):
            sec.pop("ts_api_key", None); sec.pop("ts_api_key_saved", None)
            old = sec.get("ts_oauth")
            sec["ts_oauth"] = {"id": arg["client_id"].strip(), "secret": arg["client_secret"].strip()}
            save_secrets(sec)
            _cache.pop("ts_token", None)
            try:
                ts_api("GET", "/tailnet/-/devices")
            except Exception as e:
                if old:
                    sec["ts_oauth"] = old
                else:
                    sec.pop("ts_oauth")
                save_secrets(sec)
                _cache.pop("ts_token", None)
                return {"ok": False, "error": f"Tailscale API 驗證失敗：{e}"}
        save_secrets(sec)
        log_event(who, "更新踢人設定")
        return {"ok": True, **kick_status()}
    if name == "notify_pref":
        notify.set_pref(arg.get("kind"), arg.get("on"))
        return {"ok": True}
    if name == "notify_test":
        notify.send("security", "測試通知", "如果你看到這則通知，推播就設定成功了 🎉", "/")
        return {"ok": True}
    if name == "notify_read":
        notify.mark_read()
        return {"ok": True}
    if name == "notify_unsub":
        notify.unsubscribe(arg.get("endpoint_tail") and next((s["endpoint"] for s in notify.state()["subs"] if s["endpoint"].endswith(arg["endpoint_tail"])), None))
        return {"ok": True}
    if name == "msg_done":
        msgs = load_msgs()
        for m in msgs:
            if m["id"] == arg.get("id"):
                m["done"] = bool(arg.get("done", True))
                m["reply"] = str(arg.get("reply") or m.get("reply") or "")[:300]
        save_msgs(msgs)
        return {"ok": True}
    if name == "msg_delete":
        save_msgs([m for m in load_msgs() if m["id"] != arg.get("id")])
        return {"ok": True}
    if name == "share_revoke":
        return share_revoke(str(arg.get("id")))
    if name == "backup_now":
        return run_backup(who)
    if name == "backup_toggle":
        st = backup_state()
        st["enabled"] = bool(arg.get("on"))
        backup_save(st)
        return {"ok": True}
    if name == "sec_unban":
        security.unban(str(arg.get("ip")))
        log_event(who, f"解除封鎖 {arg.get('ip')}")
        return {"ok": True}
    if name == "sec_ban":
        ip = str(arg.get("ip") or "").strip()
        if not re.match(r"^[0-9a-fA-F:.]{3,45}$", ip) or ip in _shared_ips() or ip.startswith(("127.", "100.")):
            return {"ok": False, "error": "這個位址不能封鎖"}
        security.ban(ip, float(arg.get("hours") or 24), "手動封鎖")
        log_event(who, f"手動封鎖 {ip}")
        return {"ok": True}
    if name == "sec_selftest":
        if _selftest["running"]:
            return {"ok": False, "error": "測試正在跑"}
        threading.Thread(target=run_selftest, daemon=True).start()
        return {"ok": True}
    if name == "sec_rescan":
        _cache.pop("sec-checks", None)
        _cache.pop("sec-policy", None)
        return {"ok": True}
    if name == "arrival_toggle":
        prefs = arrival_prefs()
        prefs[str(arg.get("id"))] = bool(arg.get("on"))
        with open(ARRIVAL_FILE, "w") as f:
            json.dump(prefs, f)
        MON["arrival"].pop(str(arg.get("id")), None)
        return {"ok": True}
    if name == "portal_rotate":
        return portal_rotate(str(arg.get("login", "")), who)
    if name == "proxy_rotate":
        return proxy_rotate(str(arg.get("target", "")), who)
    if name == "members_save":
        return members_save(arg, who)
    if name == "open_sharing":
        run(["open", "x-apple.systempreferences:com.apple.Sharing-Settings.extension"])
        log_event(who, "在 Mac 上打開「共享」設定")
        return {"ok": True}
    if name == "stop_service":
        port = int(arg.get("port", 0))
        e = listening().get(port)
        if not e or e["proc"] in NOISE or port in {c[1] for c in CORE}:
            return {"ok": False, "error": "這個服務不能從這裡停止"}
        os.kill(e["pid"], 15)
        log_event(who, f"停止 port {port} 的 {e['proc']}（pid {e['pid']}）")
        return {"ok": True}
    if name == "display_sleep":
        run(["pmset", "displaysleepnow"])
        log_event(who, "關閉 Mac 螢幕")
        return {"ok": True}
    if name == "open_url":
        url = str(arg.get("url", "")).strip()
        if not re.match(r"^https?://", url):
            return {"ok": False, "error": "只能開 http/https 網址"}
        run(["open", url])
        log_event(who, f"在 Mac 開啟網址：{url}")
        return {"ok": True}
    if name == "keep_awake":
        on = bool(arg.get("on"))
        if on and (_caffeinate is None or _caffeinate.poll() is not None):
            _caffeinate = subprocess.Popen(["caffeinate", "-i"])
        elif not on and _caffeinate is not None:
            _caffeinate.terminate()
            _caffeinate = None
        log_event(who, "防止睡眠：" + ("開" if on else "關"))
        return {"ok": True}
    if name == "screenshot":
        path = os.path.join(HERE, ".screenshot.jpg")
        code, _, err = run(["screencapture", "-x", "-t", "jpg", path], timeout=10)
        if code != 0 or not os.path.exists(path) or os.path.getsize(path) == 0:
            return {"ok": False, "error": err.strip() or "截圖失敗：請到「系統設定 → 隱私權與安全性 → 螢幕與系統錄音」允許 python3"}
        run(["sips", "-Z", "1600", path], timeout=10)
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        os.remove(path)
        log_event(who, "擷取 Mac 螢幕")
        return {"ok": True, "image": "data:image/jpeg;base64," + data}
    if name == "ts_ping":
        target = str(arg.get("target", ""))
        if not re.match(r"^[A-Za-z0-9.\-:]+$", target):
            return {"ok": False, "error": "bad target"}
        code, out, err = run([TAILSCALE, "ping", "-c", "3", "--timeout", "3s", target], timeout=15)
        return {"ok": code == 0, "output": (out + err).strip()}
    if name == "netcheck":
        return ts_netcheck()
    # --- AdGuard ---
    if name == "agh_protection":
        body = {"enabled": bool(arg.get("enabled"))}
        if not body["enabled"] and arg.get("minutes"):
            body["duration"] = int(arg["minutes"]) * 60000
        agh("protection", "POST", body)
        log_event(who, "擋廣告：" + ("開啟" if body["enabled"] else f"暫停 {arg.get('minutes') or '∞'} 分鐘"))
        return {"ok": True}
    if name == "agh_rule":
        domain = str(arg.get("domain", "")).strip().lower()
        kind = arg.get("kind")  # block | allow | remove
        if not re.match(r"^[a-z0-9.\-*]+$", domain):
            return {"ok": False, "error": "網域格式不對"}
        rules = [r for r in agh("filtering/status").get("user_rules") or [] if r]
        forms = {f"||{domain}^", f"@@||{domain}^"}
        rules = [r for r in rules if r not in forms]
        if kind == "block":
            rules.append(f"||{domain}^")
        elif kind == "allow":
            rules.append(f"@@||{domain}^")
        agh("filtering/set_rules", "POST", {"rules": rules})
        log_event(who, {"block": "封鎖", "allow": "放行", "remove": "移除規則"}.get(kind, kind) + f"：{domain}")
        return {"ok": True}
    if name == "agh_cache_clear":
        agh("cache_clear", "POST")
        log_event(who, "清除 DNS 快取")
        return {"ok": True}
    if name == "agh_refresh":
        try:
            agh("filtering/refresh", "POST", {"whitelist": False}, timeout=60)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        log_event(who, "更新過濾清單")
        return {"ok": True}
    if name == "agh_filter_toggle":
        fid = int(arg["id"])
        f = next(f for f in agh("filtering/status")["filters"] if f["id"] == fid)
        agh("filtering/set_url", "POST", {"url": f["url"], "whitelist": False,
                                          "data": {"name": f["name"], "url": f["url"], "enabled": bool(arg.get("enabled"))}})
        log_event(who, f"過濾清單「{f['name']}」：" + ("啟用" if arg.get("enabled") else "停用"))
        return {"ok": True}
    if name == "agh_services_set":
        ids = [str(i) for i in arg.get("ids", [])]
        cur = agh("blocked_services/get")
        agh("blocked_services/update", "PUT", {"ids": ids, "schedule": cur.get("schedule") or {"time_zone": "Local"}})
        log_event(who, f"封鎖 App/網站：{', '.join(ids) or '（無）'}")
        return {"ok": True}
    if name == "agh_restart":
        code, _, err = run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{AGH_LABEL}"])
        log_event(who, "重新啟動 AdGuard Home")
        return {"ok": code == 0, "error": err.strip()}
    return {"ok": False, "error": f"unknown action {name}"}


# ---------- Kicking devices (Tailscale API) ----------

_kick_fails = {"count": 0, "until": 0}


def load_secrets():
    try:
        with open(SECRETS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_secrets(d):
    fd = os.open(SECRETS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.chmod(SECRETS_FILE, 0o600)


def hash_pw(pw, salt=None, iters=300_000):
    salt = salt or os.urandom(16).hex()
    return {"salt": salt, "iters": iters,
            "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), iters).hex()}


def check_kick_pw(pw, who):
    """Constant-time check with a lockout after 5 wrong tries."""
    now = time.time()
    if _kick_fails["until"] > now:
        return f"密碼錯太多次，請 {int(_kick_fails['until'] - now) // 60 + 1} 分鐘後再試"
    rec = load_secrets().get("kick_pw")
    if not rec:
        return "還沒設定踢人密碼"
    if hmac.compare_digest(hash_pw(pw or "", rec["salt"], rec["iters"])["hash"], rec["hash"]):
        _kick_fails["count"] = 0
        return None
    _kick_fails["count"] += 1
    log_event("安全", f"踢人密碼錯誤（第 {_kick_fails['count']} 次）by {who}")
    security.record("kick_pw", None, f"第 {_kick_fails['count']} 次", who=who)
    if _kick_fails["count"] >= 5:
        _kick_fails.update(count=0, until=now + 900)
        log_event("安全", "踢人功能因密碼錯誤過多鎖定 15 分鐘")
        notify.send("security", "踢人密碼連續輸錯 5 次", f"已鎖定 15 分鐘（{who}）", "/#settings", urgent=True)
        return "密碼錯太多次，鎖定 15 分鐘"
    return f"密碼錯誤（還剩 {5 - _kick_fails['count']} 次）"


def ts_api_token():
    sec = load_secrets()
    if sec.get("ts_api_key"):
        return sec["ts_api_key"]
    oauth = sec.get("ts_oauth") or {}
    if not oauth.get("id") or not oauth.get("secret"):
        raise RuntimeError("還沒連結 Tailscale API")
    tok = _cache.get("ts_token")
    if tok and tok[0] > time.time() + 60:
        return tok[1]
    body = urllib.parse.urlencode({"client_id": oauth["id"], "client_secret": oauth["secret"]}).encode()
    with urllib.request.urlopen(urllib.request.Request(TS_API + "/oauth/token", data=body), timeout=10) as r:
        d = json.load(r)
    _cache["ts_token"] = (time.time() + int(d.get("expires_in", 3600)), d["access_token"])
    return d["access_token"]


def ts_api(method, path):
    req = urllib.request.Request(TS_API + path, method=method)
    req.add_header("Authorization", "Bearer " + ts_api_token())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Tailscale API {e.code}: {e.read().decode(errors='replace')[:200]}")


def kick_status():
    sec = load_secrets()
    return {"has_password": bool(sec.get("kick_pw")),
            "has_api": bool(sec.get("ts_api_key") or (sec.get("ts_oauth") or {}).get("id")),
            "api_saved_at": sec.get("ts_api_key_saved"),
            "locked_until": _kick_fails["until"] if _kick_fails["until"] > time.time() else None}


# ---------- Per-person permissions (Tailscale ACL + AdGuard clients) ----------

_policy_lock = threading.Lock()
_policy_state = {"hash": None, "last_error": None, "last_applied": None}


def normalize_person(p):
    """Clean one person record; also migrates the old {perms: {...}} format."""
    old = p.get("perms") or {}
    services = p.get("services")
    if services is None:
        services = [k for k in ("dns", "remote", "files") if old.get(k)]
    sched = p.get("schedule") or {}
    flt = p.get("filter") or {}
    return {
        "login": str(p.get("login", "")).strip(),
        "note": str(p.get("note", ""))[:40],
        "enabled": p.get("enabled", True) is not False,
        "exit": bool(p.get("exit", old.get("exit", False))),
        "services": [k for k in services if k in MAC_SERVICES],
        "ports": sorted({int(x) for x in p.get("ports") or [] if str(x).isdigit() and 1 <= int(x) <= 65535}),
        "devices": [str(x) for x in p.get("devices") or []],
        "expires": p.get("expires") if re.match(r"^\d{4}-\d{2}-\d{2}$", str(p.get("expires") or "")) else None,
        "schedule": {"on": bool(sched.get("on")), "days": sorted({int(d) for d in sched.get("days", list(range(7))) if 0 <= int(d) <= 6}),
                     "start": sched.get("start") if re.match(r"^\d{2}:\d{2}$", str(sched.get("start") or "")) else "00:00",
                     "end": sched.get("end") if re.match(r"^\d{2}:\d{2}$", str(sched.get("end") or "")) else "23:59"},
        "filter": {"on": bool(flt.get("on")), **{k: bool(flt.get(k)) for k in FILTER_OPTS},
                   "blocked": [str(x) for x in flt.get("blocked") or [] if re.match(r"^[a-z0-9_]+$", str(x))]},
        "caps": [c for c in p.get("caps") or [] if c in PANEL_CAPS],
        "sr": {"on": bool((p.get("sr") or {}).get("on")),
               "id": (p.get("sr") or {}).get("id") if valid_uuid((p.get("sr") or {}).get("id")) else ""},
        "portal": p.get("portal") if re.match(r"^[0-9a-f]{32}$", str(p.get("portal") or "")) else "",
        "daily_min": max(0, min(1440, int(p.get("daily_min") or 0))),
        "drive": {"on": bool((p.get("drive") or {}).get("on")),
                  "quota_gb": max(0.0, float((p.get("drive") or {}).get("quota_gb") or 0)),
                  "shared": (p.get("drive") or {}).get("shared") if (p.get("drive") or {}).get("shared") in ("none", "ro", "rw") else "none",
                  # iPhone Shortcuts photo backup; on by default so existing members keep working
                  "backup": (p.get("drive") or {}).get("backup", True) is not False},
    }


def valid_uuid(v):
    try:
        return str(uuidlib.UUID(str(v))) == str(v).lower()
    except ValueError:
        return False


def is_ts_login(login):
    """Tailscale identities are emails; a plain name is a Shadowrocket-only member."""
    return "@" in login


def load_members():
    try:
        with open(PERMS_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    d["people"] = [normalize_person(p) for p in d.get("people") or []]
    d.setdefault("managed", False)
    return d


def save_members(d):
    fd = os.open(PERMS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)


def person_active(p, now=None):
    """(active, reason) taking enabled flag, expiry date and weekly schedule into account (Mac local time)."""
    now = now or time.localtime()
    if not p["enabled"]:
        return False, "已停用"
    if p["expires"] and time.strftime("%Y-%m-%d", now) > p["expires"]:
        return False, "已過期"
    sc = p["schedule"]
    if p.get("daily_min") and USAGE["minutes"].get(p["login"], 0) >= p["daily_min"]:
        return False, "今日時數已用完"
    if sc["on"]:
        hm = time.strftime("%H:%M", now)
        wd = now.tm_wday  # 0 = Monday
        if sc["start"] <= sc["end"]:
            inside = wd in sc["days"] and sc["start"] <= hm < sc["end"]
        else:  # overnight window, e.g. 22:00-02:00 belongs to the day it started
            inside = (wd in sc["days"] and hm >= sc["start"]) or (((wd - 1) % 7) in sc["days"] and hm < sc["end"])
        if not inside:
            return False, "不在允許時段"
    return True, "生效中"


def ts_api_raw(method, path, body=None, headers=None):
    req = urllib.request.Request(TS_API + path, method=method, data=body)
    req.add_header("Authorization", "Bearer " + ts_api_token())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def get_policy():
    code, hdr, raw = ts_api_raw("GET", "/tailnet/-/acl", headers={"Accept": "application/json"})
    if code == 403:
        raise PermissionError("OAuth 金鑰沒有 Policy file 權限")
    if code != 200:
        raise RuntimeError(f"讀取規則失敗 {code}: {raw.decode(errors='replace')[:200]}")
    return json.loads(raw), hdr.get("ETag") or hdr.get("Etag")


def api_devices():
    def fetch():
        devs = ts_api("GET", "/tailnet/-/devices").get("devices", [])
        return [{"id": d.get("nodeId") or d.get("id"),
                 "name": (d.get("name") or "").split(".")[0] if d.get("hostname") in (None, "", "localhost") else d.get("hostname"),
                 "user": d.get("user"),
                 "os": d.get("os"), "ips": d.get("addresses") or []} for d in devs]
    return cached("api_devices", 60, fetch)


def policy_mode(pol):
    """Describe the live policy: allow-all / managed by panel / something else."""
    rules = (pol.get("grants") or []) + (pol.get("acls") or [])
    for r in rules:
        src, dst = r.get("src") or [], r.get("dst") or []
        if "*" in src and ("*" in dst or "*:*" in dst):
            return "allow_all"
    if (pol.get("hosts") or {}).get("homemac") and any(o in (r.get("src") or []) for r in rules for o in OWNERS):
        return "managed"
    return "custom"


def managed_sections(people, mac_ip, devices, now=None):
    """The part of the ACL the panel owns, for the people active right now."""
    owner = sorted(OWNERS)[0]
    by_id = {d["id"]: d for d in devices}
    grants = [
        {"src": [owner], "dst": ["*"], "ip": ["*"]},
        {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
        # The member portal and the Shadowrocket endpoint live on :8443, which is public through the Funnel anyway.
        # Inside the tailnet the hostname resolves to the Mac's tailnet IP, so members need this or their own
        # page won't open while Tailscale is on (kept even when expired, so they can see why).
        {"src": ["autogroup:member"], "dst": ["homemac"], "ip": [f"tcp:{PROXY_PORT}"]},
    ]
    for p in sorted(people, key=lambda x: x["login"]):
        if p["login"] in OWNERS or not is_ts_login(p["login"]) or not person_active(p, now)[0]:
            continue
        if p["exit"]:
            grants.append({"src": [p["login"]], "dst": ["autogroup:internet"], "ip": ["*"]})
        ports = [pt for k in p["services"] for pt in MAC_SERVICES[k][1]] + [f"tcp:{n}" for n in p["ports"]]
        if ports:
            grants.append({"src": [p["login"]], "dst": ["homemac"], "ip": sorted(set(ports))})
        dev_ips = sorted({ip for i in p["devices"] if i in by_id and by_id[i]["user"] in OWNERS
                          for ip in by_id[i]["ips"] if ip != mac_ip})
        if dev_ips:
            grants.append({"src": [p["login"]], "dst": dev_ips, "ip": ["*"]})
    return {"hosts": {"homemac": mac_ip}, "grants": grants,
            "tests": [{"src": owner, "accept": [f"{mac_ip}:443", f"{mac_ip}:5900", f"{mac_ip}:53"]}]}


def build_policy(live, managed):
    pol = {k: v for k, v in live.items() if k not in MANAGED_KEYS}
    pol.setdefault("tagOwners", {"tag:homepanel": ["autogroup:admin"]})
    # only the owner may publish devices with Funnel (the default lets every member expose their own devices)
    attrs = []
    for a in pol.get("nodeAttrs") or []:
        if "funnel" in (a.get("attr") or []):
            a = {**a, "target": sorted(OWNERS)}
        attrs.append(a)
    if attrs:
        pol["nodeAttrs"] = attrs
    pol.update(managed)
    return pol


def apply_policy(reason, who="系統", force=False):
    """Push the ACL for whoever is active now. Skips the API call when nothing changed."""
    with _policy_lock:
        data = load_members()
        st = ts_status()
        if not st.get("ok"):
            raise RuntimeError("讀不到 Tailscale 狀態")
        mac_ip = st["self"]["ips"][0]
        managed = managed_sections(data["people"], mac_ip, api_devices())
        h = hashlib.sha256(json.dumps(managed, sort_keys=True).encode()).hexdigest()
        if h == _policy_state["hash"] and not force:
            return False
        live, etag = get_policy()
        if not force and all(live.get(k) == v for k, v in managed.items()):
            _policy_state["hash"] = h
            return False
        body = json.dumps(build_policy(live, managed)).encode()
        code, _, raw = ts_api_raw("POST", "/tailnet/-/acl/validate", body, {"Content-Type": "application/json"})
        msg = (json.loads(raw).get("message") if raw.strip().startswith(b"{") else None) if raw else None
        if code != 200 or msg:
            raise RuntimeError("Tailscale 驗證規則失敗：" + (msg or raw.decode(errors="replace")[:300]))
        hdrs = {"Content-Type": "application/json"}
        if etag:
            hdrs["If-Match"] = etag
        code, _, raw = ts_api_raw("POST", "/tailnet/-/acl", body, hdrs)
        if code == 412:
            raise RuntimeError("規則剛剛在別處被改過，請重新整理後再存一次")
        if code != 200:
            raise RuntimeError(f"套用規則失敗 {code}: {raw.decode(errors='replace')[:300]}")
        _policy_state.update(hash=h, last_error=None, last_applied=time.time())
        active = [p["login"] for p in data["people"] if person_active(p)[0]]
        log_event(who, f"🔐 權限已更新（{reason}）：生效中 {', '.join(active) or '無訪客'}")
        return True


def sync_agh_clients():
    """One AdGuard persistent client per member with personal filtering, keyed by their devices' tailnet IPs."""
    data = load_members()
    devs = api_devices()
    want = {}
    for p in data["people"]:
        f = p["filter"]
        ips = sorted({ip for d in devs if d["user"] == p["login"] for ip in d["ips"]})
        if not f["on"] or not ips:
            continue
        want["ts:" + p["login"]] = {
            "name": "ts:" + p["login"], "ids": ips, "use_global_settings": False,
            "filtering_enabled": f["ads"], "parental_enabled": f["adult"], "safebrowsing_enabled": f["malware"],
            "safe_search": {"enabled": f["safesearch"], "bing": True, "duckduckgo": True, "ecosia": True, "google": True,
                            "pixabay": True, "yandex": True, "youtube": True},
            "use_global_blocked_services": False, "blocked_services": sorted(f["blocked"]),
            "blocked_services_schedule": {"time_zone": "Local"},
            "upstreams": [], "tags": [], "ignore_querylog": False, "ignore_statistics": False,
        }
    have = {c["name"]: c for c in (agh("clients").get("clients") or []) if c.get("name", "").startswith("ts:")}
    keys = ["ids", "filtering_enabled", "parental_enabled", "safebrowsing_enabled", "blocked_services"]
    for name, c in have.items():
        if name not in want:
            agh("clients/delete", "POST", {"name": name})
    for name, c in want.items():
        old = have.get(name)
        if old and all(sorted(old.get(k) or []) == sorted(c[k]) if isinstance(c[k], list) else old.get(k) == c[k] for k in keys) \
                and (old.get("safe_search") or {}).get("enabled") == c["safe_search"]["enabled"]:
            continue
        if old:
            agh("clients/update", "POST", {"name": name, "data": c})
        else:
            agh("clients/add", "POST", c)


def policy_scheduler():
    """Every minute: re-apply the ACL when expiry/schedule flips someone's access; resync AdGuard every 5 min."""
    n = 0
    while True:
        time.sleep(60)
        n += 1
        try:
            data = load_members()
            if data.get("managed") and kick_status()["has_api"]:
                apply_policy("排程")
                if n % 5 == 0:
                    sync_agh_clients()
            if data.get("sr_owner"):
                apply_xray("排程")
            usage_tick()
            monitor_tick()
            macstats.record()
            _policy_state["last_error"] = None
        except Exception as e:
            if _policy_state["last_error"] != str(e):
                log_event("系統", f"⚠️ 自動套用權限失敗：{e}")
            _policy_state["last_error"] = str(e)


def member_role(login):
    """('owner', all caps) / ('member', caps) / (None, reason)."""
    if login in OWNERS:
        return "owner", list(PANEL_CAPS)
    p = next((x for x in load_members()["people"] if x["login"] == login), None)
    if not p:
        return None, "你沒有權限使用這個控制台"
    ok, why = person_active(p)
    if not ok:
        return None, f"你的權限目前無效（{why}）"
    if "panel" not in p["services"] or not p["caps"]:
        return None, "你沒有控制台權限"
    return "member", p["caps"]


def members_overview():
    st = ts_status()
    mac_ip = st["self"]["ips"][0] if st.get("ok") else None
    data = load_members()
    out = {"ok": True, "owner": sorted(OWNERS)[0], "mac_ip": mac_ip, "api": None, "mode": None,
           "managed": data["managed"], "people": data["people"], "devices": [],
           "services": {k: v[0] for k, v in MAC_SERVICES.items()}, "caps": PANEL_CAPS, "filters": FILTER_OPTS,
           "last_error": _policy_state["last_error"], "last_applied": _policy_state["last_applied"]}
    for p in out["people"]:
        p["active"], p["status"] = person_active(p)
        p["portal_url"] = portal_url(p["portal"])
    if not kick_status()["has_api"]:
        out["api"] = "none"
        return out
    try:
        out["devices"] = api_devices()
    except Exception as e:
        out["devices_error"] = str(e)
    try:
        live, _ = get_policy()
        out["api"] = "ok"
        out["mode"] = policy_mode(live)
    except PermissionError as e:
        out["api"], out["api_error"] = "no_policy_scope", str(e)
    except Exception as e:
        out["api"], out["api_error"] = "error", str(e)
    known = {p["login"] for p in out["people"]}
    for d in out["devices"]:
        u = d.get("user")
        if u and u not in known and u not in OWNERS:
            np_ = normalize_person({"login": u})
            np_["new"], np_["active"], np_["status"] = True, True, "新加入・尚無權限"
            out["people"].append(np_)
            known.add(u)
    return out


def members_save(arg, who):
    err = check_kick_pw(arg.get("password"), who)
    if err:
        return {"ok": False, "error": err}
    people, seen = [], set()
    for raw in arg.get("people") or []:
        p = normalize_person(raw)
        if not (re.match(r"^[^\s@]+@[^\s@]+$", p["login"]) or re.match(r"^[^\s@<>\"'&]{1,32}$", p["login"])) \
                or p["login"] in OWNERS or p["login"] in seen:
            continue
        if not is_ts_login(p["login"]):
            if not settings.SHADOWROCKET:
                continue  # a plain name is a Shadowrocket-only member, which this install doesn't offer
            p["sr"]["on"] = True  # a plain name only makes sense as a Shadowrocket account
        elif not settings.SHADOWROCKET:
            p["sr"]["on"] = False
        if p["sr"]["on"] and not p["sr"]["id"]:
            p["sr"]["id"] = str(uuidlib.uuid4())
        if not p["portal"]:
            p["portal"] = os.urandom(16).hex()
        if p["caps"] and "panel" not in p["services"]:
            p["services"].append("panel")
        if p["filter"]["on"] and "dns" not in p["services"]:
            p["services"].append("dns")
        seen.add(p["login"])
        people.append(p)
    old = load_members()
    save_members({**old, "people": people, "managed": True})
    try:
        apply_policy("手動儲存", who, force=True)
    except Exception as e:
        save_members(old)
        return {"ok": False, "error": str(e)}
    warn = []
    try:
        apply_xray("手動儲存", who)
    except Exception as e:
        warn.append(f"Shadowrocket 設定更新失敗：{e}")
    try:
        sync_agh_clients()
    except Exception as e:
        warn.append(f"個人上網限制同步失敗：{e}")
    for w in warn:
        log_event("系統", "⚠️ " + w)
    return {"ok": True, **({"warning": "權限已套用，但" + "；".join(warn)} if warn else {})}


def member_device_ips(login):
    try:
        return {ip for d in api_devices() if d["user"] == login for ip in d["ips"]}
    except Exception:
        return set()


# ---------- Shadowrocket accounts (Xray) ----------

_xray_lock = threading.Lock()
_xray_error = {"msg": None}


def xray_stats(reset=False):
    """{email: {"up": bytes, "down": bytes}} since Xray last started (or last reset)."""
    cmd = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}", "-pattern", "user>>>"] + (["-reset"] if reset else [])
    code, out, _ = run(cmd, timeout=5)
    res = {}
    if code != 0:
        return res
    try:
        for st in json.loads(out).get("stat") or []:
            parts = st["name"].split(">>>")
            if len(parts) == 4:
                res.setdefault(parts[1], {"up": 0, "down": 0})["up" if parts[3] == "uplink" else "down"] += int(st.get("value") or 0)
    except (ValueError, KeyError):
        pass
    return res


def _load_usage():
    try:
        with open(XRAY_USAGE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def xray_usage():
    """Lifetime traffic per account = saved totals + live counters."""
    tot = _load_usage()
    for k, v in xray_stats().items():
        t = tot.setdefault(k, {"up": 0, "down": 0})
        t["up"] += v["up"]
        t["down"] += v["down"]
    return tot


def _bank_usage():
    """Move live counters into usage.json (called right before Xray restarts)."""
    live = xray_stats(reset=True)
    if not live:
        return
    tot = _load_usage()
    for k, v in live.items():
        t = tot.setdefault(k, {"up": 0, "down": 0})
        t["up"] += v["up"]
        t["down"] += v["down"]
    fd = os.open(XRAY_USAGE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(tot, f)


def ensure_sr_owner():
    """Owner account + shared WebSocket path live in members.json; the first run replaces the hand-made key."""
    data = load_members()
    changed = False
    st = ts_status()
    if st.get("ok") and data.get("sr_host") != st["self"]["dns"]:
        data["sr_host"] = st["self"]["dns"]
        changed = True
    if st.get("ok") and data.get("sr_mac_ip") != st["self"]["ips"][0]:
        data["sr_mac_ip"] = st["self"]["ips"][0]
        changed = True
    if not valid_uuid((data.get("sr_owner") or {}).get("id")):
        data["sr_owner"] = {"id": str(uuidlib.uuid4())}
        changed = True
    if not re.match(r"^/[a-z0-9]{12,}$", str(data.get("sr_path") or "")):
        data["sr_path"] = "/" + os.urandom(8).hex()
        changed = True
    for person in data["people"]:
        if not person["portal"]:  # members created before the portal existed
            person["portal"] = os.urandom(16).hex()
            changed = True
    if changed:
        save_members(data)
    return data


def own_addresses():
    """Every address assigned to this Mac (public IPv6 included) — a proxy user must never reach it."""
    import ipaddress
    out = run(["ifconfig"])[1]
    addrs = set(re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", out))
    for a in re.findall(r"\binet6 ([0-9a-f:]+)", out):
        ip = ipaddress.ip_address(a)
        if ip.is_global:  # temporary addresses rotate, so block the whole /64 (also covers LAN devices)
            addrs.add(str(ipaddress.ip_network(f"{a}/64", strict=False)))
    return sorted(addrs)


def blocked_ips():
    return ["0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
            "169.254.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "64:ff9b::/96", "fc00::/7",  # ::ffff:a.b.c.d is matched as IPv4 by Xray
            "fe80::/10", "ff00::/8", "fd7a:115c:a1e0::/48"] + own_addresses()


def build_xray_config(data):
    owner = sorted(OWNERS)[0]
    clients = [{"id": data["sr_owner"]["id"], "email": owner}]
    rules = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "outboundTag": "block", "ip": blocked_ips()},
        {"type": "field", "outboundTag": "block", "domain": ["localhost", "domain:ts.net", "domain:local"]},
    ]
    host = data.get("sr_host")
    if host and data.get("sr_mac_ip"):
        # only the owner's account: panel / AdGuard UI / web remote desktop via the Mac's own tailnet IP (still behind the app lock)
        rules.insert(1, {"type": "field", "user": [owner], "domain": [f"full:{host}"], "port": "443,3443,6443",
                         "outboundTag": "owner-tailnet"})
    if host:
        # the portal lives on the public Funnel port; resolve it with public DNS so it can't hit the tailnet IP
        rules.insert(1, {"type": "field", "domain": [f"full:{host}"], "port": str(PROXY_PORT), "outboundTag": "public"})
    for p in sorted(data["people"], key=lambda x: x["login"]):
        if not (p["sr"]["on"] and p["sr"]["id"] and person_active(p)[0]):
            continue
        clients.append({"id": p["sr"]["id"], "email": p["login"]})
        f = p["filter"]
        if not f["on"]:
            continue
        lists = (["geosite:category-ads-all"] if f["ads"] else []) + (["geosite:category-porn"] if f["adult"] else []) + \
                ["geosite:" + SR_GEOSITE[b] for b in f["blocked"] if b in SR_GEOSITE]
        if lists:
            rules.append({"type": "field", "user": [p["login"]], "outboundTag": "block", "domain": sorted(set(lists))})
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "shadowrocket", "listen": "127.0.0.1", "port": 10080, "protocol": "vless",
             "settings": {"clients": clients, "decryption": "none"},
             "streamSettings": {"network": "ws", "wsSettings": {"path": data["sr_path"]}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "api", "listen": "127.0.0.1", "port": int(XRAY_API.split(":")[1]), "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}},
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "public", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "owner-tailnet", "protocol": "freedom", "settings": {"redirect": f"{data.get('sr_mac_ip') or '127.0.0.1'}:0"}},
        ],
        "dns": {"servers": ([{"address": "1.1.1.1", "domains": [f"full:{host}"]}] if host else []) + ["localhost"]},
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def apply_xray(reason, who="系統"):
    """Regenerate the Xray config; restart only when it actually changed."""
    if not settings.SHADOWROCKET:
        return False
    with _xray_lock:
        data = ensure_sr_owner()
        cfg = build_xray_config(data)
        new = json.dumps(cfg, indent=1, ensure_ascii=False)
        try:
            with open(XRAY_CONFIG) as f:
                if f.read() == new:
                    return False
        except OSError:
            pass
        tmp = os.path.join(XRAY_DIR, "config.next.json")  # xray picks the format from the extension
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new)
        code, out, err = run([XRAY_BIN, "run", "-test", "-config", tmp], timeout=20)
        if code != 0:
            os.remove(tmp)
            _xray_error["msg"] = "Xray 設定檢查失敗，仍在使用舊設定：" + (out + err).strip()[-200:]
            raise RuntimeError(_xray_error["msg"])
        _xray_error["msg"] = None
        _bank_usage()
        os.replace(tmp, XRAY_CONFIG)
        run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{XRAY_LABEL}"])
        n = len(cfg["inbounds"][0]["settings"]["clients"])
        log_event(who, f"Shadowrocket 設定已更新（{reason}）：{n} 個帳號可用")
        return True


def sr_link(uid, path, host, label):
    q = urllib.parse.urlencode({"encryption": "none", "security": "tls", "sni": host, "type": "ws",
                                "host": host, "path": path, "fp": "chrome"})
    return f"vless://{uid}@{host}:{PROXY_PORT}?{q}#" + urllib.parse.quote(label)


def proxy_info():
    data = ensure_sr_owner()
    st = ts_status()
    host = st["self"]["dns"] if st.get("ok") else None
    code, out, _ = run([TAILSCALE, "funnel", "status", "--json"])
    try:
        fs = json.loads(out) if code == 0 else {}
    except ValueError:
        fs = {}
    code, o, _ = run(["launchctl", "print", f"gui/{os.getuid()}/{XRAY_LABEL}"])
    usage = xray_usage()
    owner = sorted(OWNERS)[0]
    accounts = [{"login": owner, "owner": True, "active": True, "status": "生效中", "filter": False,
                 "link": sr_link(data["sr_owner"]["id"], data["sr_path"], host, "家裡的 Mac") if host else None,
                 "usage": usage.get(owner, {"up": 0, "down": 0})}]
    for p in data["people"]:
        if not p["sr"]["on"] or not p["sr"]["id"]:
            continue
        ok, why = person_active(p)
        accounts.append({"login": p["login"], "owner": False, "active": ok, "status": why, "filter": p["filter"]["on"],
                         "link": sr_link(p["sr"]["id"], data["sr_path"], host, "家裡的 Mac・" + p["login"]) if host else None,
                         "usage": usage.get(p["login"], {"up": 0, "down": 0})})
    return {"ok": True, "host": host, "port": PROXY_PORT,
            "funnel": bool((fs.get("AllowFunnel") or {}).get(f"{host}:{PROXY_PORT}")),
            "running": code == 0 and "state = running" in o, "accounts": accounts, "error": _xray_error["msg"]}


def proxy_rotate(target, who):
    data = ensure_sr_owner()
    if target in OWNERS:
        data["sr_owner"]["id"] = str(uuidlib.uuid4())
    else:
        p = next((x for x in data["people"] if x["login"] == target and x["sr"]["on"]), None)
        if not p:
            return {"ok": False, "error": "找不到這個 Shadowrocket 帳號"}
        p["sr"]["id"] = str(uuidlib.uuid4())
    save_members(data)
    apply_xray(f"更換 {target} 的金鑰", who)
    log_event(who, f"更換 Shadowrocket 金鑰：{target}（舊的立即失效）")
    return {"ok": True}


# ---------- Member portal (public, read-only, token per person) ----------

_portal_fails = collections.defaultdict(list)


# ---------- security page: health checks + self attack test ----------
SECURITY_DIR = os.path.join(os.path.dirname(HERE), "security")
SELFTEST_TOKEN = os.urandom(16).hex()   # lets the self test's forged-identity probe skip the push alert
_selftest = {"running": False, "at": None, "results": [], "progress": ""}


def _chk(cid, label, status, detail, fix=""):
    return {"id": cid, "label": label, "status": status, "detail": detail, "fix": fix}


def security_checks():
    out = []
    fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate", "--getstealthmode"])[1]
    on, stealth = "enabled" in fw.split("\n")[0], "stealth mode is on" in fw
    out.append(_chk("firewall", "macOS 防火牆", "ok" if on else "bad", "已開啟" if on else "沒有開啟", "執行加固腳本"))
    out.append(_chk("stealth", "隱身模式（不回應探測）", "ok" if stealth else "warn", "已開啟" if stealth else "沒有開啟", "執行加固腳本"))
    # pf can only be read as root: the LaunchDaemon from harden.sh writes its status here every 10 minutes
    pf_path = os.path.join(SECURITY_DIR, "pf-status.txt")
    try:
        lines = open(pf_path).read().split("\n")
        age = time.time() - int(lines[0])
        rules = int(lines[2]) if len(lines) > 2 and lines[2].strip().isdigit() else 0
        good = "Enabled" in lines[1] and rules > 0
        out.append(_chk("pf", "遠端服務只允許 Tailscale（封包過濾）", "ok" if good and age < 1800 else "warn",
                        (f"已啟用，{rules} 條規則" if good else "規則沒有載入") + (f"（{int(age // 60)} 分鐘前回報）" if age < 1800 else "（超過 30 分鐘沒有回報）"),
                        "sudo bash ~/homeserver/security/harden.sh"))
    except (OSError, ValueError, IndexError):
        out.append(_chk("pf", "遠端服務只允許 Tailscale（封包過濾）", "warn", "還沒確認：家裡 Wi-Fi 上的人可能連得到 SSH、檔案共享、螢幕共享",
                        "sudo bash ~/homeserver/security/harden.sh"))
    listen = run(["netstat", "-anv", "-p", "tcp"])[1]
    open_ports = {int(m) for m in re.findall(r"\*\.(\d+)\s+\*\.\*\s+LISTEN", listen)}
    names = {22: "SSH", 445: "檔案共享", 5900: "螢幕共享", 5000: "AirPlay", 7000: "AirPlay"}
    exposed = [f"{names[k]}（{k}）" for k in sorted(names) if k in open_ports]
    pf_ok = out[-1]["status"] == "ok"
    out.append(_chk("ports", "對所有網路開放的服務", "ok" if not exposed or pf_ok else "warn",
                    ("、".join(exposed) + ("：已由封包過濾限制為只有 Tailscale" if pf_ok else "：目前家裡網路也連得到")) if exposed else "沒有",
                    "" if pf_ok else "sudo bash ~/homeserver/security/harden.sh"))
    fv = run(["fdesetup", "status"])[1]
    out.append(_chk("filevault", "FileVault 磁碟加密", "ok" if "On" in fv else "warn", "已開啟" if "On" in fv else "沒有開啟：Mac 被偷時資料可以直接讀出來",
                    "系統設定 → 隱私權與安全性 → FileVault（注意：開啟後停電重開機要先輸入密碼，伺服器才會回來）"))
    sip = run(["csrutil", "status"])[1]
    out.append(_chk("sip", "系統完整性保護（SIP）", "ok" if "enabled" in sip else "bad", "已開啟" if "enabled" in sip else "被關掉了"))
    gk = run(["spctl", "--status"])[1] + run(["spctl", "--status"])[2]
    out.append(_chk("gatekeeper", "Gatekeeper（擋未簽署程式）", "ok" if "enabled" in gk else "warn", "已開啟" if "enabled" in gk else "已關閉"))
    au = run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"])[1].strip()
    out.append(_chk("updates", "自動安裝安全性更新", "ok" if au == "1" else "warn", "已開啟" if au == "1" else "沒有開啟", "系統設定 → 一般 → 軟體更新 → 自動更新"))
    try:
        acc = agh("access/list")
        allowed = acc.get("allowed_clients") or []
        good = allowed and all(x in ("127.0.0.1", "::1", "100.64.0.0/10", "fd7a:115c:a1e0::/48") for x in allowed)
        out.append(_chk("dns", "擋廣告 DNS 只服務自己人", "ok" if good else "warn", "只接受本機和 Tailscale" if good else "任何人都能查詢（可能被拿去做 DNS 放大攻擊）"))
    except Exception as e:
        out.append(_chk("dns", "擋廣告 DNS 只服務自己人", "unknown", f"讀不到 AdGuard：{e}"))
    srv = run([TAILSCALE, "serve", "status"])[1]
    funnels = re.findall(r"https://\S+?:(\d+) \(Funnel on\)", srv)
    out.append(_chk("funnel", "對網路公開的入口", "ok" if funnels == ["8443"] else "warn",
                    "只有 8443（Shadowrocket 和成員網頁）" if funnels == ["8443"] else f"公開中：{', '.join(funnels) or '無'}"))
    try:
        pol = cached("sec-policy", 600, lambda: get_policy()[0])
        fun = [a for a in pol.get("nodeAttrs") or [] if "funnel" in (a.get("attr") or [])]
        good = all(set(a.get("target") or []) <= OWNERS for a in fun)
        out.append(_chk("acl_funnel", "只有你能開 Funnel", "ok" if good else "warn", "是" if good else "所有成員都能把自己的裝置公開到網路上"))
    except Exception as e:
        out.append(_chk("acl_funnel", "只有你能開 Funnel", "unknown", f"讀不到 Tailscale 規則：{e}"))
    owner = sorted(OWNERS)[0]
    rec = LOCK_STORE.get(owner)
    out.append(_chk("lock", "控制台密碼／Face ID", "ok" if rec.get("pin") else "warn",
                    ("已設定" + ("，有 Face ID" if rec.get("passkeys") else "")) if rec.get("pin") else "還沒設定"))
    bad_perm = []
    for f in [os.path.join(HERE, x) for x in ("members.json", "secrets.json", "notify.json", "shares.json", "security-events.json", "security-bans.json")] + \
             [XRAY_CONFIG, os.path.join(os.path.dirname(HERE), "credentials.txt"), os.path.join(os.path.dirname(HERE), "AdGuardHome", "AdGuardHome.yaml")]:
        if os.path.exists(f) and os.stat(f).st_mode & 0o077:
            bad_perm.append(os.path.basename(f))
    out.append(_chk("perms", "機密檔案只有你讀得到", "ok" if not bad_perm else "bad", "全部正確" if not bad_perm else "權限太寬：" + "、".join(bad_perm)))
    try:
        if not settings.SHADOWROCKET:
            raise FileNotFoundError("Shadowrocket 功能沒有啟用")
        cfg = json.load(open(XRAY_CONFIG))
        blocked = {ip for r in cfg.get("routing", {}).get("rules", []) if r.get("outboundTag") == "block" for ip in r.get("ip", [])}
        need = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
        out.append(_chk("xray", "Shadowrocket 不能連進家裡內網", "ok" if need <= blocked else "bad", "已擋內網和 Tailscale 位址" if need <= blocked else "沒有擋內網"))
    except Exception as e:
        out.append(_chk("xray", "Shadowrocket 不能連進家裡內網", "info" if not settings.SHADOWROCKET else "unknown", str(e)))
    vers = {"Tailscale": run([TAILSCALE, "version"])[1].split("\n")[0], "Xray": (run([XRAY_BIN, "version"])[1].split() or ["", "?"])[1],
            "AdGuard": (safe(lambda: agh("status")) or {}).get("version", "?")}
    out.append(_chk("versions", "軟體版本", "info", "・".join(f"{k} {v}" for k, v in vers.items()), "AdGuard 和 Xray 不會自動更新，偶爾檢查新版"))
    s_ = security.summary()
    out.append(_chk("autoban", "自動封鎖猜網址的人", "ok", f"同一個位址一小時猜錯 {security.BAN_RULES['bad_token']} 次就封鎖 {security.BAN_HOURS} 小時；目前封鎖 {len(s_['bans'])} 個"))
    return out


def run_selftest():
    """Attack our own portal/panel from localhost the way an outsider would, and report what held."""
    import socket as _s
    import http.client
    _selftest.update(running=True, results=[], progress="準備中")
    res = _selftest["results"]
    tok = next((p["portal"] for p in load_members()["people"] if p["portal"]), None)
    who = ["selftest"]  # each test pretends to be a different address, so one test's rate limit can't skew the next

    def req(method, path, port=PORTAL_PORT, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, body=body, headers={"X-Forwarded-For": who[0], **(headers or {})})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def test(name, desc, fn):
        _selftest["progress"] = name
        who[0] = "selftest-" + os.urandom(4).hex()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"測試出錯：{e}"
        res.append({"name": name, "desc": desc, "ok": ok, "detail": detail})

    def t_version():
        st, h, _ = req("GET", "/p/s/" + "0" * 24 + "/")
        sv = h.get("Server", "")
        return "Python" not in sv, f"伺服器自稱「{sv}」"

    def t_headers():
        _, h, _ = req("GET", "/p/s/" + "0" * 24 + "/")
        need = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        miss = [k for k in need if k not in h]
        return not miss, "都有" if not miss else "缺少 " + "、".join(miss)

    def t_ratelimit():
        codes = [req("GET", "/p/" + os.urandom(16).hex() + "/")[0] for _ in range(21)]
        return codes[-1] == 429, f"連猜 21 次，第 {codes.index(429) + 1 if 429 in codes else '—'} 次開始被擋"

    def t_traversal():
        if not tok:
            return True, "沒有成員可以測（略過）"
        bad = []
        for pth in ["/mine/../../", "/mine/%2e%2e/%2e%2e/", "/../../members.json", "/mine/..%2f..%2f"]:
            st, _, data = req("GET", f"/p/{tok}/drive/list?path=" + urllib.parse.quote(pth, safe="%/"))
            if st == 200 and b'"items"' in data and b"members.json" in data:
                bad.append(pth)
        st, _, _ = req("GET", f"/p/{tok}/../../members.json")
        return not bad and st != 200, "所有 ../ 變化型都被擋" if not bad else "被突破：" + "、".join(bad)

    def t_oversize():
        if not tok:
            return True, "略過"
        c = _s.create_connection(("127.0.0.1", PORTAL_PORT), timeout=8)
        c.sendall(f"POST /p/{tok}/message HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {who[0]}\r\nX-Requested-With: portal\r\nContent-Length: 2147483647\r\n\r\n{{".encode())
        t0 = time.time()
        line = c.recv(100).split(b"\r\n")[0].decode()
        c.close()
        return "413" in line and time.time() - t0 < 3, f"宣稱 2GB 的請求在 {time.time() - t0:.1f} 秒內被拒（{line[9:]}）"

    def t_slowloris():
        socks = []
        for _ in range(10):
            c = _s.create_connection(("127.0.0.1", PORTAL_PORT), timeout=30)
            c.sendall(b"GET /p/s/ HTTP/1.1\r\nHost: x\r\n")
            socks.append(c)
        _selftest["progress"] = "慢速連線（等 18 秒）"
        time.sleep(18)
        held = 0
        for c in socks:
            try:
                c.settimeout(0.5)
                held += 1 if c.recv(10) != b"" else 0
            except _s.timeout:
                held += 1
            except OSError:
                pass
            c.close()
        return held == 0, f"10 條只送一半的連線，18 秒後還被佔住 {held} 條"

    def t_csrf():
        if not tok:
            return True, "略過"
        st, _, _ = req("POST", f"/p/{tok}/message", headers={"Origin": "https://evil.example", "X-Requested-With": "portal",
                                                            "Content-Type": "application/json"}, body=b'{"kind":"other","text":"x"}')
        return st == 403, f"假網站送出的留言 → {st}"

    def t_spoof():
        st, _, _ = req("GET", "/api/overview", port=PORT, headers={"Tailscale-User-Login": sorted(OWNERS)[0], "X-Selftest": SELFTEST_TOKEN})
        return st == 403, f"本機程式冒充你的身分連控制台 → {st}"

    def t_methods():
        bad = [m for m in ("PUT", "DELETE", "PATCH") if req(m, "/p/s/" + "0" * 24 + "/")[0] not in (405, 501)]
        return not bad, "PUT／DELETE／PATCH 都不接受" if not bad else "接受了：" + "、".join(bad)

    def t_html():
        risky = {"text/html", "image/svg+xml", "application/xhtml+xml", "text/xml", "application/javascript"} & drive.PREVIEW
        return not risky, "網頁、SVG、程式檔一律當下載，不會在瀏覽器執行" if not risky else "會直接顯示：" + "、".join(risky)

    for args in [("版本不外洩", "伺服器不告訴別人用了哪個版本", t_version), ("安全標頭", "HSTS、CSP、禁止被嵌入", t_headers),
                 ("猜網址會被擋", "一直猜成員網址會被限速", t_ratelimit), ("路徑穿越", "用 ../ 跑出自己的資料夾", t_traversal),
                 ("超大請求", "假裝要傳 2GB 卡住伺服器", t_oversize), ("跨站請求", "別的網站偷偷幫你送出操作", t_csrf),
                 ("偽造身分", "冒充你連進控制台", t_spoof), ("奇怪的請求方法", "PUT／DELETE 之類", t_methods),
                 ("上傳網頁檔", "上傳含程式的檔案讓別人打開", t_html), ("慢速連線攻擊", "開很多連線慢慢送，拖垮伺服器", t_slowloris)]:
        test(*args)
    _selftest.update(running=False, at=time.time(), progress="")
    failed = [r["name"] for r in res if not r["ok"]]
    log_event("安全", f"自我攻擊測試：{len(res) - len(failed)}/{len(res)} 項擋下" + (f"，沒擋下：{'、'.join(failed)}" if failed else ""))


def _shared_ips():
    ips = {cached("pubip", 300, public_ip)}
    ips.discard(None)
    security.configure(exempt=ips)
    return ips


def portal_url(token):
    host = load_members().get("sr_host")
    return f"https://{host}:{PROXY_PORT}{PORTAL_PREFIX}/{token}/" if host and token else None


def service_names():
    def fetch():
        return {x["id"]: x["name"] for x in agh("blocked_services/all").get("blocked_services", [])}
    try:
        return cached("svc_names", 3600, fetch)
    except Exception:
        return {}


def portal_me(p):
    """Everything a member may see about themselves — nothing about anyone else."""
    data = load_members()
    host = data.get("sr_host")
    ok, why = person_active(p)
    names = service_names()
    try:
        devs = [{"name": d["name"], "os": d["os"]} for d in api_devices() if d["user"] == p["login"]]
    except Exception:
        devs = []
    usage = xray_usage().get(p["login"], {"up": 0, "down": 0}) if p["sr"]["on"] else None
    ts = is_ts_login(p["login"])
    owner_devs = []
    if ts and p["devices"]:
        try:
            owner_devs = [d["name"] for d in api_devices() if d["id"] in p["devices"] and d["user"] in OWNERS]
        except Exception:
            pass
    return {
        "ok": True, "name": p["login"], "note": p["note"], "active": ok, "status": why, "enabled": p["enabled"],
        "expires": p["expires"], "schedule": p["schedule"], "weekdays": WEEKDAYS,
        "tailscale": {"member": ts, "exit": ts and p["exit"],
                      "services": [MAC_SERVICES[k][0] for k in p["services"]] if ts else [],
                      "ports": p["ports"] if ts else [], "devices": devs, "owner_devices": owner_devs,
                      "mac": host},
        "filter": {"on": p["filter"]["on"], **({k: p["filter"][k] for k in FILTER_OPTS} if p["filter"]["on"] else {}),
                   "blocked": [names.get(b, b) for b in p["filter"]["blocked"]] if p["filter"]["on"] else []},
        "filter_labels": FILTER_OPTS,
        "shadowrocket": {"on": settings.SHADOWROCKET and p["sr"]["on"] and bool(p["sr"]["id"]),
                         "link": sr_link(p["sr"]["id"], data["sr_path"], host, "家裡的 Mac") if p["sr"]["on"] and p["sr"]["id"] and host else None,
                         "usage": usage},
        "drive": {"on": bool(member_scope(p)), "quota": int(p["drive"]["quota_gb"] * (1 << 30)), "shared": p["drive"]["shared"],
                  "backup": p["drive"]["backup"],
                  "used": drive.dir_size(drive.user_dir(p["login"])) if p["drive"]["on"] and drive.mounted() and os.path.isdir(drive.user_dir(p["login"])) else 0},
        "daily_min": p["daily_min"], "minutes_today": USAGE["minutes"].get(p["login"], 0),
        "panel": ts and "panel" in p["services"] and bool(p["caps"]),
        "panel_url": f"https://{host}/" if host else None,
    }


def portal_person(token):
    if not re.match(r"^[0-9a-f]{32}$", token or ""):
        return None
    return next((p for p in load_members()["people"] if p["portal"] and hmac.compare_digest(p["portal"], token)), None)


def portal_rotate(login, who):
    data = load_members()
    p = next((x for x in data["people"] if x["login"] == login), None)
    if not p:
        return {"ok": False, "error": "找不到這個成員"}
    p["portal"] = os.urandom(16).hex()
    save_members(data)
    log_event(who, f"更換客戶端網址：{login}（舊網址立即失效）")
    return {"ok": True, "url": portal_url(p["portal"])}


class PortalHandler(BaseHTTPRequestHandler):
    """Public, read-only. Never trusts Tailscale identity headers — only the secret token in the URL."""
    server_version = "home"
    sys_version = ""   # don't advertise the Python version

    def version_string(self):
        return self.server_version
    timeout = 15       # the request line + headers must arrive within 15 s (slowloris); see gate() for the body

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v.replace("img-src 'self' data: https://avatars.githubusercontent.com https://*.googleusercontent.com", "img-src 'self' data:"))
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def client_ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def send_body(self, body, ctype, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def not_found(self, kind="bad_token"):
        ip = self.client_ip()
        now = time.time()
        _portal_fails[ip] = [t for t in _portal_fails[ip] if now - t < 600] + [now]
        security.record(kind, ip, urllib.parse.urlparse(self.path).path[:80])
        self.send_body("找不到頁面".encode(), "text/plain; charset=utf-8", 404)

    def gate(self):
        """Banned addresses and address-level rate limit. Returns False when the request was answered."""
        self.connection.settimeout(120)  # headers are in; give slow phones time for big downloads / uploads
        ip = self.client_ip()
        if security.is_banned(ip):
            if _thr.ok("bannedhit-" + ip, 300):
                security.record("banned_hit", ip, urllib.parse.urlparse(self.path).path[:80])
            self.send_body("forbidden".encode(), "text/plain; charset=utf-8", 403)
            return False
        # every Shadowrocket member reaches the portal from our own public IP, so it gets a much higher limit
        limit = 200 if ip in _shared_ips() else 20
        if len([t for t in _portal_fails[ip] if time.time() - t < 600]) >= limit:
            if _thr.ok("ratelim-" + ip, 600):
                security.record("rate_limited", ip)
            self.send_body("嘗試太多次，請稍後再試".encode(), "text/plain; charset=utf-8", 429)
            return False
        return True

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith(PORTAL_PREFIX + "/"):  # serve strips the mount point in some versions, keep both
            path = path[len(PORTAL_PREFIX):]
        parts = [x for x in path.split("/") if x]
        ip = self.client_ip()
        if not self.gate():
            return
        if parts and parts[0] == "s":
            return self.share_get(parts[1:])
        p = portal_person(parts[0]) if parts else None
        if not p:
            self.not_found()
            return
        rest = parts[1:]
        try:
            if not rest:
                with open(os.path.join(HERE, "portal.html"), encoding="utf-8") as f:
                    page = f.read()
                with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                    idx = f.read()
                style = idx[idx.index("<style>") + 7:idx.index("</style>")]
                self.send_body(page.replace("/*SHARED_STYLE*/", style).encode(), "text/html; charset=utf-8")
            elif rest == ["me"]:
                d = portal_me(p)
                d["client_ip"] = ip
                d["via_tailnet"] = ip.startswith("100.") or ip.startswith("fd7a:115c:a1e0")
                self.send_body(json.dumps(d, ensure_ascii=False).encode(), "application/json; charset=utf-8")
            elif rest == ["speed", "down"]:
                speed_down(self, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("mb", ["10"])[0])
            elif rest == ["messages"]:
                self.send_body(json.dumps({"ok": True, "items": [m for m in load_msgs() if m["from"] == p["login"]][:20], "types": MSG_TYPES},
                                          ensure_ascii=False).encode(), "application/json; charset=utf-8")
            elif len(rest) == 2 and rest[0] == "drive":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                drive_route(self, member_scope(p), rest[1], q, "GET", p["login"])
            elif rest in (["qrcode.js"], ["drive.js"]):
                with open(os.path.join(HERE, "static", rest[0]), "rb") as f:
                    self.send_body(f.read(), "text/javascript; charset=utf-8")
            elif rest == ["icon.png"]:
                with open(os.path.join(HERE, "static", "icon-180.png"), "rb") as f:
                    self.send_body(f.read(), "image/png")
            else:
                self.not_found()
        except Exception as e:
            log_event("系統", f"⚠️ 客戶端網頁錯誤：{type(e).__name__}: {e}")
            self.send_body(json.dumps({"ok": False, "error": "伺服器發生錯誤，請稍後再試"}, ensure_ascii=False).encode(), "application/json; charset=utf-8", 500)

    def send_json(self, obj, code=200):
        self.send_body(json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8", code)

    def read_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_JSON:
            security.record("oversize", self.client_ip(), f"{n} bytes")
            raise TooLarge("資料太大")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        try:
            self._do_post()
        except TooLarge:
            self.close_connection = True
            self.send_json({"ok": False, "error": "資料太大"}, 413)
        except Exception as e:
            log_event("系統", f"⚠️ 客戶端網頁錯誤：{type(e).__name__}: {e}")
            self.send_json({"ok": False, "error": "伺服器發生錯誤，請稍後再試"}, 500)

    def _do_post(self):
        """Only cloud-drive writes are allowed, same-origin only, and only inside the person's own scope."""
        if not self.gate():
            return
        path = urllib.parse.urlparse(self.path).path
        if path.startswith(PORTAL_PREFIX + "/"):
            path = path[len(PORTAL_PREFIX):]
        parts = [x for x in path.split("/") if x]
        origin = self.headers.get("Origin")
        site = self.headers.get("Sec-Fetch-Site")
        cross = (site and site != "same-origin") or (origin and urllib.parse.urlparse(origin).netloc != self.headers.get("Host"))
        if parts[:1] == ["s"] and len(parts) == 3 and parts[2] == "unlock" and not cross:
            return self.share_unlock(parts[1])
        p = portal_person(parts[0]) if parts else None
        if not p or self.headers.get("X-Requested-With") != "portal" or cross:
            if cross:
                security.record("csrf", self.client_ip(), f"{origin or site} → {path[:60]}")
            elif not p:
                _portal_fails[self.client_ip()].append(time.time())
                security.record("bad_token", self.client_ip(), "POST " + path[:60])
            self.send_body(b"forbidden", "text/plain", 403)
            return
        if parts[1:] == ["message"]:
            try:
                body = self.read_json()
                return self.send_json(msg_post(p["login"], body.get("kind"), body.get("text")))
            except ValueError as e:
                return self.send_json({"ok": False, "error": str(e)}, 400)
        if parts[1:] == ["speed", "up"]:
            return self.send_json(speed_up(self))
        if len(parts) != 3 or parts[1] != "drive":
            self.send_body(b"forbidden", "text/plain", 403)
            return
        if parts[2] == "upload" and not p["drive"]["backup"]:
            # automatic backup = the Shortcuts flags, or any upload that doesn't come from a browser page (no Origin / Sec-Fetch-Site)
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if qs.get("mkdir") == ["1"] or qs.get("skip_existing") == ["1"] or not (origin or site):
                self.close_connection = True
                security.record("backup_denied", self.client_ip(), p["login"])
                return self.send_json({"ok": False, "error": "管理員沒有開放你使用照片自動備份"}, 403)
        drive_route(self, member_scope(p), parts[2], urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query), "POST", p["login"])

    # ----- public share links -----
    def _share(self, sid):
        sh = load_shares().get(sid) if re.match(r"^[0-9a-f]{24}$", sid or "") else None
        return sh

    def _share_ok_cookie(self, sid, sh):
        if not sh["password"]:
            return True
        want = hmac.new(notify._vapid_key(notify.state()).private_numbers().private_value.to_bytes(32, "big"), sid.encode(), "sha256").hexdigest()
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sh_" + sid and hmac.compare_digest(v, want):
                return True
        return False

    def share_unlock(self, sid):
        sh = self._share(sid)
        if not sh:
            return self.not_found("share_bad")
        now = time.time()
        _share_fails[sid] = [t for t in _share_fails[sid] if now - t < 900]
        if len(_share_fails[sid]) >= 5:
            return self.send_json({"ok": False, "error": "密碼錯太多次，請 15 分鐘後再試"}, 429)
        pw = str(self.read_json().get("password", ""))
        if not sh["password"] or not hmac.compare_digest(applock._hash_pin(pw, sh["password"]["salt"])["hash"], sh["password"]["hash"]):
            _share_fails[sid].append(now)
            security.record("share_pw", self.client_ip(), sid[:8] + "…")
            return self.send_json({"ok": False, "error": "密碼錯誤"}, 403)
        val = hmac.new(notify._vapid_key(notify.state()).private_numbers().private_value.to_bytes(32, "big"), sid.encode(), "sha256").hexdigest()
        self.send_response(200)
        self.send_header("Set-Cookie", f"sh_{sid}={val}; Path={PORTAL_PREFIX}/s/{sid}/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400")
        body = b'{"ok": true}'
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def share_get(self, rest):
        sid = rest[0] if rest else ""
        sh = self._share(sid)
        if not sh:
            return self.not_found("share_bad")
        dead = share_dead(sh)
        op = rest[1] if len(rest) > 1 else ""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if not op:
            with open(os.path.join(HERE, "share.html"), encoding="utf-8") as f:
                page = f.read()
            with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                idx = f.read()
            style = idx[idx.index("<style>") + 7:idx.index("</style>")]
            return self.send_body(page.replace("/*SHARED_STYLE*/", style).encode(), "text/html; charset=utf-8")
        if op in ("qrcode.js", "drive.js", "icon.png"):
            fn = "icon-180.png" if op == "icon.png" else op
            with open(os.path.join(HERE, "static", fn), "rb") as f:
                return self.send_body(f.read(), "image/png" if op == "icon.png" else "text/javascript; charset=utf-8")
        info = {"ok": True, "name": sh["name"], "dir": sh["dir"], "dead": dead, "locked": not self._share_ok_cookie(sid, sh),
                "expires": sh["expires"], "left": (sh["max"] - sh["downloads"]) if sh["max"] else None, "creator": sh["creator"].split("@")[0]}
        if op == "info":
            return self.send_json(info)
        if dead or info["locked"]:
            return self.send_json({"ok": False, "error": dead or "需要密碼"}, 403)
        scope = share_scope(sh)
        path = q.get("path", ["/s"])[0]
        if not sh["dir"] and path not in ("/s", "/s/" + sh["name"]):
            return self.not_found("share_bad")
        try:
            if op == "list":
                d = drive.list_dir(scope, path)
                if not sh["dir"]:
                    d["items"] = [i for i in d["items"] if i["name"] == sh["name"]]
                return self.send_json(d)
            if op == "get":
                _, real = drive.resolve(scope, path)
                if not os.path.isfile(real):
                    raise drive.DriveError("這不是檔案", 400)
                rng = self.headers.get("Range", "")
                if not rng or rng.startswith("bytes=0-"):
                    shares = load_shares()
                    if sid in shares:
                        shares[sid]["downloads"] += 1
                        save_shares(shares)
                return drive.send_file(self, scope, path, inline=q.get("inline", ["0"])[0] == "1")
            if op == "info":
                return self.send_json(drive.info(scope, path))
            if op == "text":
                return self.send_json(drive.text_preview(scope, path))
            if op == "zip":
                if not sh["dir"]:
                    return self.not_found("share_bad")
                shares = load_shares()
                if sid in shares:
                    shares[sid]["downloads"] += 1
                    save_shares(shares)
                return drive.send_zip(self, scope, path)
            if op == "thumb":
                tp = drive.thumb(scope, path, 1600 if q.get("size", [""])[0] == "big" else 360)
                with open(tp, "rb") as f:
                    return self.send_body(f.read(), "image/jpeg")
        except drive.DriveError as e:
            return self.send_json({"ok": False, "error": str(e)}, e.code)
        self.not_found("share_bad")

    def do_PUT(self):
        self.send_body(b"read-only", "text/plain", 405)

    do_DELETE = do_PATCH = do_PUT


# ---------- Cloud drive (external disk) ----------

def owner_scope():
    owner = sorted(OWNERS)[0]
    return {"mine": drive.Root(drive.user_dir(owner), True, "我的檔案", desc="你的私人空間，只有你看得到"),
            "shared": drive.Root(drive.SHARED_DIR, True, "共用", desc="全家一起用；每個成員能不能看、能不能改由你決定"),
            "users": drive.Root(drive.USERS_DIR, True, "成員資料夾", desc="每位成員的「我的檔案」，只有你看得到全部"),
            "mac": drive.Root(BOX_DIR, True, "Mac 傳輸箱", desc="存在 Mac 內建硬碟（不是外接硬碟），適合臨時傳檔")}


def member_scope(p):
    d = p["drive"]
    if not d["on"] or not person_active(p)[0]:
        return {}
    scope = {"mine": drive.Root(drive.user_dir(p["login"]), True, "我的檔案", int(d["quota_gb"] * (1 << 30)), p["login"],
                                desc="你的私人空間，只有你和管理員看得到")}
    if d["shared"] != "none":
        scope["shared"] = drive.Root(drive.SHARED_DIR, d["shared"] == "rw", "共用",
                                     desc="全家一起用的資料夾・" + ("你可以上傳和修改" if d["shared"] == "rw" else "你只能看和下載"))
    return scope


# ---------- external disk stats ----------

_disk_io = {"mbs": 0.0, "tps": 0.0, "at": 0, "dev": None}
_disk_kinds = {"at": 0, "data": None, "busy": False}
KIND_LABEL = {"image": "照片", "video": "影片", "audio": "音樂", "doc": "文件", "pdf": "文件", "archive": "壓縮檔", "file": "其他"}


def _plist(args):
    code, out, _ = run(args, timeout=15)
    if code != 0:
        return {}
    import plistlib
    try:
        return plistlib.loads(out.encode())
    except Exception:
        return {}


def disk_hw():
    """Model / format / bus / link speed of the drive holding the cloud (cached: these never change while plugged in)."""
    def fetch():
        vol = _plist(["diskutil", "info", "-plist", drive.DRIVE_ROOT.rsplit("/HomeCloud", 1)[0]])
        whole = vol.get("ParentWholeDisk")
        dev = _plist(["diskutil", "info", "-plist", whole]) if whole else {}
        speed, inside = None, False
        media = dev.get("MediaName") or ""
        for line in run(["system_profiler", "SPUSBHostDataType"], timeout=20)[1].splitlines():
            t = line.strip()
            if media and t == media + ":":  # the device section is headed by its model name
                inside = True
            elif inside and t.startswith("Link Speed:"):
                speed = t.split(":", 1)[1].strip()
                break
        return {"volume": vol.get("VolumeName"), "model": (dev.get("IORegistryEntryName") or dev.get("MediaName") or "").replace(" Media", ""),
                "format": vol.get("FilesystemUserVisibleName"), "bus": vol.get("BusProtocol"), "link": speed,
                "smart": vol.get("SMARTStatus"), "ssd": dev.get("SolidState"), "whole": whole,
                "capacity": dev.get("TotalSize") or vol.get("TotalSize")}
    return cached("disk_hw", 3600, fetch)


def _io_monitor():
    """Stream `iostat` for the cloud disk; restarts when the disk comes back after being unplugged."""
    while True:
        try:
            whole = disk_hw().get("whole") if drive.mounted() else None
            if not whole:
                time.sleep(10)
                continue
            _disk_io["dev"] = whole
            proc = subprocess.Popen(["iostat", "-d", "-w", "2", whole], stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                f = line.split()
                if len(f) == 3 and f[0].replace(".", "", 1).isdigit():
                    _disk_io.update(tps=float(f[1]), mbs=float(f[2]), at=time.time())
                if not drive.mounted():
                    proc.kill()
                    break
        except Exception:
            pass
        _cache.pop("disk_hw", None)
        time.sleep(5)


def _scan_kinds():
    """Walk the cloud once and total size / count per kind of file."""
    if _disk_kinds["busy"] or not drive.mounted():
        return
    _disk_kinds["busy"] = True
    try:
        tot = {}
        files = folders = 0
        for dp, dns, fns in os.walk(drive.DRIVE_ROOT):
            dns[:] = [d for d in dns if not d.startswith(".") and d not in drive.HIDDEN]
            folders += len(dns)
            for fn in fns:
                if fn.startswith(".") or fn.endswith(".uploading"):
                    continue
                try:
                    size = os.lstat(os.path.join(dp, fn)).st_size
                except OSError:
                    continue
                label = KIND_LABEL.get(drive.kind(fn, False), "其他")
                t = tot.setdefault(label, {"size": 0, "count": 0})
                t["size"] += size
                t["count"] += 1
                files += 1
        _disk_kinds.update(at=time.time(), data={"kinds": tot, "files": files, "folders": folders})
    finally:
        _disk_kinds["busy"] = False


def drive_stats():
    if not drive.mounted():
        return {"ok": True, "mounted": False}
    if time.time() - _disk_kinds["at"] > 300:
        threading.Thread(target=_scan_kinds, daemon=True).start()
    du = shutil.disk_usage(drive.DRIVE_ROOT.rsplit("/HomeCloud", 1)[0])
    cloud = drive.dir_size(drive.DRIVE_ROOT, ttl=120)
    return {"ok": True, "mounted": True, "hw": disk_hw(), "total": du.total, "used": du.total - du.free, "free": du.free,
            "cloud": cloud, "other": max(0, du.total - du.free - cloud), "kinds": _disk_kinds["data"],
            "kinds_at": _disk_kinds["at"] or None,
            "io": {k: _disk_io[k] for k in ("mbs", "tps")} if time.time() - _disk_io["at"] < 10 else None}


def drive_usage():
    """Owner view: disk + per-person usage and quota."""
    data = load_members()
    people = []
    for p in data["people"]:
        if not p["drive"]["on"]:
            continue
        path = drive.user_dir(p["login"])
        people.append({"login": p["login"], "quota": int(p["drive"]["quota_gb"] * (1 << 30)), "shared": p["drive"]["shared"],
                       "used": drive.dir_size(path) if drive.mounted() and os.path.isdir(path) else 0})
    owner = sorted(OWNERS)[0]
    return {"ok": True, "mounted": drive.mounted(), "disk": drive.disk(), "people": people,
            "shared_used": drive.dir_size(drive.SHARED_DIR) if drive.mounted() and os.path.isdir(drive.SHARED_DIR) else 0,
            "mine_used": drive.dir_size(drive.user_dir(owner)) if drive.mounted() and os.path.isdir(drive.user_dir(owner)) else 0}


def drive_route(h, scope, sub, q, method, who):
    """Shared by the owner panel (/api/drive/*) and the member portal (/p/<token>/drive/*)."""
    arg = lambda k: (q.get(k) or [""])[0]
    try:
        if method == "GET":
            if sub == "roots":
                return h.send_json({"ok": True, "mounted": drive.mounted(), "roots": drive.roots_info(scope) if drive.mounted() else []})
            if sub == "list":
                return h.send_json(drive.list_dir(scope, arg("path")))
            if sub == "get":
                return drive.send_file(h, scope, arg("path"), inline=arg("inline") == "1")
            if sub == "info":
                return h.send_json(drive.info(scope, arg("path")))
            if sub == "text":
                return h.send_json(drive.text_preview(scope, arg("path")))
            if sub == "zip":
                log_event(who, f"雲端下載資料夾（ZIP）：{arg('path')}")
                return drive.send_zip(h, scope, arg("path"))
            if sub == "thumb":
                path = drive.thumb(scope, arg("path"), 1600 if arg("size") == "big" else 360)
                with open(path, "rb") as f:
                    body = f.read()
                h.send_response(200)
                h.send_header("Content-Type", "image/jpeg")
                h.send_header("Cache-Control", "private, max-age=604800")
                h.send_header("Content-Length", str(len(body)))
                h.end_headers()
                h.wfile.write(body)
                return
            if sub == "search":
                return h.send_json(drive.search(scope, arg("q")))
            if sub == "trash":
                return h.send_json(drive.trash_list(scope))
            if sub == "shares":
                return h.send_json(share_list(who))
        else:
            if sub == "upload":
                raw = h.headers.get("X-Filename", "")
                try:  # some clients (iPhone Shortcuts) send raw UTF-8, which http.server decodes as Latin-1
                    raw = raw.encode("latin-1").decode("utf-8")
                except (UnicodeEncodeError, UnicodeDecodeError):
                    pass
                name = urllib.parse.unquote(raw)
                n = int(h.headers.get("Content-Length", 0))
                if arg("mkdir") == "1":  # iPhone Shortcut backups: create the folder path on first upload
                    root, real = drive.resolve(scope, "/" + arg("path").strip("/").split("/")[0])
                    _need = os.path.join(real, *arg("path").strip("/").split("/")[1:])
                    drive._need_write(root)
                    os.makedirs(_need, exist_ok=True)
                if arg("skip_existing") == "1":
                    _, folder = drive.resolve(scope, arg("path"))
                    target = os.path.join(folder, drive.clean_name(name))
                    if os.path.isfile(target) and os.path.getsize(target) == n:
                        h.rfile.read(n)
                        return h.send_json({"ok": True, "skipped": True, "name": os.path.basename(target)})
                res = drive.upload(scope, arg("path"), name, n, h.rfile)
                log_event(who, f"雲端上傳：{arg('path')}/{res['name']}")
                return h.send_json(res)
            body = h.read_json()
            path = body.get("path", "")
            if sub == "mkdir":
                res = drive.mkdir(scope, path, body.get("name"))
                log_event(who, f"雲端新增資料夾：{path}/{body.get('name')}")
                return h.send_json(res)
            if sub == "delete":
                res = drive.trash_item(scope, path)
                log_event(who, f"雲端刪除（移到垃圾桶）：{path}")
                return h.send_json(res)
            if sub == "restore":
                res = drive.trash_restore(scope, body.get("id"))
                log_event(who, f"雲端還原：{res['restored_to']}")
                return h.send_json(res)
            if sub == "purge":
                return h.send_json(drive.trash_purge(scope, body.get("id")))
            if sub == "empty_trash":
                return h.send_json(drive.trash_empty(scope))
            if sub == "share":
                # members may only share their own files, never the family's shared folder
                if who not in OWNERS and str(body.get("path") or "").strip("/").split("/")[0] != "mine":
                    return h.send_json({"ok": False, "error": "只能分享「我的檔案」裡的東西，共用資料夾不能分享出去"}, 403)
                return h.send_json(share_create(scope, who, body))
            if sub == "unshare":
                return h.send_json(share_revoke(str(body.get("id")), creator=None if who in OWNERS else who))
            if sub == "move":
                paths = [str(p) for p in (body.get("paths") or [])][:500]
                res = drive.move(scope, paths, str(body.get("dest") or ""))
                log_event(who, f"雲端移動 {res['moved']} 個項目到 {body.get('dest')}")
                return h.send_json(res)
            if sub == "rename":
                res = drive.rename(scope, path, body.get("name"))
                log_event(who, f"雲端改名：{path} → {body.get('name')}")
                return h.send_json(res)
        h.send_json({"ok": False, "error": "unknown"}, 404)
    except drive.DriveError as e:
        h.send_json({"ok": False, "error": str(e)}, e.code)
    except PermissionError:
        h.send_json({"ok": False, "error": "Mac 沒有允許控制台存取外接硬碟（系統設定 → 隱私權與安全性 → 完整取用磁碟 → Python）"}, 503)
    except OSError as e:
        h.send_json({"ok": False, "error": f"硬碟錯誤：{e.strerror or e}"}, 500)


LOCK_STORE = applock.Store(lambda: load_secrets(), lambda d: save_secrets(d))


def peer_process(peer_port):
    """Name of the local process that owns the client end of a loopback connection to the panel."""
    out = run(["netstat", "-anv", "-p", "tcp"], timeout=5)[1]
    want = (f"127.0.0.1.{peer_port}", f"127.0.0.1.{PORT}")
    for line in out.splitlines():
        f = line.split()
        if len(f) > 10 and (f[3], f[4]) == want:
            return f[10].rsplit(":", 1)[0]
    return None


# ---------- usage tracking: daily minutes, traffic history, time quotas ----------
USAGE_FILE = os.path.join(HERE, "usage-state.json")
USAGE = {"date": None, "minutes": {}, "history": {}, "prev_sr": {}, "prev_ts": {}}  # history[date][login] = {"up","down"}
ACTIVE_BYTES = 20_000  # more than this in a minute counts as a minute of use


def _usage_load():
    try:
        with open(USAGE_FILE) as f:
            USAGE.update(json.load(f))
    except (OSError, ValueError):
        pass


def _usage_save():
    fd = os.open(USAGE_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(USAGE, f)
    os.replace(USAGE_FILE + ".tmp", USAGE_FILE)


def usage_tick():
    """Every minute: add traffic deltas per person (Shadowrocket via Xray stats, Tailscale via device counters)."""
    today = time.strftime("%Y-%m-%d")
    if USAGE["date"] != today:
        USAGE.update(date=today, minutes={})
    hist = USAGE["history"].setdefault(today, {})
    delta = {}
    sr = xray_stats()
    for login, v in sr.items():
        prev = USAGE["prev_sr"].get(login, {"up": 0, "down": 0})
        up, down = v["up"] - prev["up"], v["down"] - prev["down"]
        if up < 0 or down < 0:  # xray restarted and counters reset
            up, down = v["up"], v["down"]
        d = delta.setdefault(login, {"up": 0, "down": 0})
        d["up"] += up
        d["down"] += down
    USAGE["prev_sr"] = sr
    st = ts_status()
    try:
        owners = {d["id"]: d["user"] for d in api_devices()}
    except Exception:
        owners = {}
    cur = {}
    for peer in st.get("peers", []) if st.get("ok") else []:
        user = owners.get(peer.get("id"))
        if not user:
            continue
        cur[peer["id"]] = {"rx": peer.get("rx", 0), "tx": peer.get("tx", 0)}
        prev = USAGE["prev_ts"].get(peer["id"])
        if prev:
            rx, tx = cur[peer["id"]]["rx"] - prev["rx"], cur[peer["id"]]["tx"] - prev["tx"]
            if rx >= 0 and tx >= 0:  # from the Mac's side: tx = what the member downloaded
                d = delta.setdefault(user, {"up": 0, "down": 0})
                d["down"] += tx
                d["up"] += rx
    USAGE["prev_ts"] = cur
    for login, d in delta.items():
        h = hist.setdefault(login, {"up": 0, "down": 0})
        h["up"] += d["up"]
        h["down"] += d["down"]
        if d["up"] + d["down"] > ACTIVE_BYTES:
            USAGE["minutes"][login] = USAGE["minutes"].get(login, 0) + 1
    for day in sorted(USAGE["history"])[:-35]:
        USAGE["history"].pop(day, None)
    _usage_save()


def member_report(login, days=14):
    """Traffic per day, minutes today and (for Tailscale members) most-visited sites from the DNS log."""
    out = []
    for i in range(days - 1, -1, -1):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        v = USAGE["history"].get(day, {}).get(login, {"up": 0, "down": 0})
        out.append({"day": day, "up": v["up"], "down": v["down"]})
    top = []
    ips = member_device_ips(login)
    if ips:
        try:
            counts = collections.Counter()
            for r in agh("querylog?limit=1000").get("data") or []:
                if r.get("client") in ips:
                    host = (r.get("question") or {}).get("name", "")
                    counts[".".join(host.split(".")[-2:])] += 1
            top = [{"domain": k, "count": v} for k, v in counts.most_common(10)]
        except Exception:
            pass
    p = next((x for x in load_members()["people"] if x["login"] == login), None)
    return {"ok": True, "days": out, "minutes_today": USAGE["minutes"].get(login, 0),
            "daily_min": p["daily_min"] if p else 0, "top": top, "dns_note": not ips}


# ---------- share links (public, via the Funnel under /p/s/<id>/) ----------
SHARES_FILE = os.path.join(HERE, "shares.json")
_share_fails = collections.defaultdict(list)


def load_shares():
    try:
        with open(SHARES_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_shares(d):
    fd = os.open(SHARES_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(SHARES_FILE + ".tmp", SHARES_FILE)


def share_create(scope, creator, arg):
    root, real = drive.resolve(scope, arg.get("path", ""))
    if real == os.path.realpath(root.path):
        raise drive.DriveError("不能分享最上層資料夾，請選裡面的資料夾或檔案")
    days = float(arg.get("days") or 0)
    sid = os.urandom(12).hex()
    pw = str(arg.get("password") or "")
    shares = load_shares()
    shares[sid] = {"creator": creator, "base": os.path.dirname(real), "name": os.path.basename(real), "dir": os.path.isdir(real),
                   "created": time.time(), "expires": time.time() + days * 86400 if days else None,
                   "max": max(0, int(arg.get("max") or 0)), "downloads": 0, "vpath": arg.get("path"),
                   "password": applock._hash_pin(pw) if pw else None}
    save_shares(shares)
    log_event(creator, f"建立分享連結：{os.path.basename(real)}")
    return {"ok": True, "id": sid, "url": share_url(sid)}


def share_url(sid):
    host = load_members().get("sr_host")
    return f"https://{host}:{PROXY_PORT}{PORTAL_PREFIX}/s/{sid}/" if host else None


def share_list(creator=None):
    out = []
    for sid, sh in load_shares().items():
        if creator and sh["creator"] != creator:
            continue
        out.append({"id": sid, "name": sh["name"], "dir": sh["dir"], "creator": sh["creator"], "created": sh["created"],
                    "expires": sh["expires"], "max": sh["max"], "downloads": sh["downloads"], "password": bool(sh["password"]),
                    "url": share_url(sid), "vpath": sh.get("vpath"), "expired": share_dead(sh)})
    return {"ok": True, "items": sorted(out, key=lambda x: -x["created"])}


def share_dead(sh):
    if sh["expires"] and time.time() > sh["expires"]:
        return "已過期"
    if sh["max"] and sh["downloads"] >= sh["max"]:
        return "下載次數已用完"
    if not os.path.exists(os.path.join(sh["base"], sh["name"])):
        return "檔案已不存在"
    return None


def share_revoke(sid, creator=None):
    shares = load_shares()
    sh = shares.get(sid)
    if not sh or (creator and sh["creator"] != creator):
        return {"ok": False, "error": "找不到這個分享"}
    shares.pop(sid)
    save_shares(shares)
    return {"ok": True}


def share_scope(sh):
    """A one-folder read-only scope rooted at the shared item (file shares use its folder, filtered to the one name)."""
    if sh["dir"]:
        return {"s": drive.Root(os.path.join(sh["base"], sh["name"]), False, sh["name"])}
    return {"s": drive.Root(sh["base"], False, sh["name"])}


# ---------- messages from members ----------
MSG_FILE = os.path.join(HERE, "messages.json")
MSG_TYPES = {"extend": "申請延長使用期限", "quota": "申請加大雲端容量", "time": "申請增加每日時數", "help": "需要幫忙", "other": "其他"}


def load_msgs():
    try:
        with open(MSG_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_msgs(m):
    fd = os.open(MSG_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(m[:300], f, ensure_ascii=False)
    os.replace(MSG_FILE + ".tmp", MSG_FILE)


def msg_post(login, kind, text):
    if kind not in MSG_TYPES:
        raise ValueError("類型不正確")
    msgs = load_msgs()
    today = time.strftime("%Y-%m-%d")
    if sum(1 for m in msgs if m["from"] == login and time.strftime("%Y-%m-%d", time.localtime(m["at"])) == today) >= 10:
        raise ValueError("今天留言太多了，請明天再試")
    m = {"id": os.urandom(6).hex(), "from": login, "kind": kind, "text": str(text or "")[:500], "at": time.time(), "done": False, "reply": ""}
    msgs.insert(0, m)
    save_msgs(msgs)
    notify.send("message", f"{login} 的留言", f"{MSG_TYPES[kind]}" + (f"：{m['text'][:80]}" if m["text"] else ""), "/#members")
    return {"ok": True}


# ---------- nightly backup of the cloud to the Mac's internal disk ----------
BACKUP_DIR = os.path.join(HOME, "homeserver", "cloud-backup")
BACKUP_STATE = os.path.join(HERE, "backup.json")


def backup_state():
    try:
        with open(BACKUP_STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"enabled": True, "last": None, "result": None, "size": 0, "running": False}


def backup_save(st):
    with open(BACKUP_STATE, "w") as f:
        json.dump(st, f, ensure_ascii=False)


def run_backup(who="系統"):
    st = backup_state()
    if st.get("running"):
        return {"ok": False, "error": "備份正在進行中"}
    if not drive.mounted():
        return {"ok": False, "error": "外接硬碟沒有接上"}
    need = drive.dir_size(drive.DRIVE_ROOT, wait=True)
    have = shutil.disk_usage(HOME).free + (drive._walk_size(BACKUP_DIR) if os.path.isdir(BACKUP_DIR) else 0)
    if need > have - (5 << 30):
        st.update(last=time.time(), result=f"空間不足：雲端有 {need / 2**30:.1f} GB，Mac 只剩 {max(0, have - (5 << 30)) / 2**30:.1f} GB 可用", running=False)
        backup_save(st)
        notify.send("backup", "雲端備份沒有執行", st["result"], "/#settings")
        return {"ok": False, "error": st["result"]}
    st["running"] = True
    backup_save(st)

    def work():
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        code, out, err = run(["rsync", "-a", "--delete", "--exclude", ".trash", "--exclude", ".thumbs", "--exclude", ".*",
                              drive.DRIVE_ROOT + "/", BACKUP_DIR + "/"], timeout=6 * 3600)
        st2 = backup_state()
        ok = code == 0
        st2.update(running=False, last=time.time(), size=need,
                   result="成功" if ok else f"失敗：{(err or out).strip()[-200:]}")
        backup_save(st2)
        log_event(who, f"雲端備份{'完成' if ok else '失敗'}（{need / 2**30:.2f} GB）")
        if not ok:
            notify.send("backup", "雲端備份失敗", st2["result"], "/#settings", urgent=True)
    threading.Thread(target=work, daemon=True).start()
    return {"ok": True}


# ---------- monitors → notifications ----------
MON = {"mounted": None, "battery_warned": False, "devices": None, "services": {}, "arrival": {}, "expiry_day": None}
_thr = notify.Throttle()
ARRIVAL_FILE = os.path.join(HERE, "arrival.json")


def arrival_prefs():
    try:
        with open(ARRIVAL_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def lan_prefix():
    m = re.search(r"\binet (\d+\.\d+\.\d+)\.\d+ netmask", run(["ifconfig", "en0"])[1])
    return m.group(1) + "." if m else "192.168."


def monitor_tick():
    # disk
    mounted = drive.mounted()
    if MON["mounted"] is not None and mounted != MON["mounted"]:
        notify.send("disk", "外接硬碟已接上" if mounted else "外接硬碟被拔掉了",
                    "雲端恢復正常" if mounted else f"雲端暫時不能用，請檢查 {settings.DRIVE_NAME} 的線", "/#cloud", urgent=not mounted)
    MON["mounted"] = mounted
    if mounted:
        du = drive.disk()
        if du and (du["free"] < 20 << 30 or du["used"] / du["total"] > .9) and _thr.ok("diskfull", 86400):
            notify.send("disk", "雲端硬碟快滿了", f"只剩 {du['free'] / 2**30:.1f} GB", "/#cloud")
    # battery
    batt = run(["pmset", "-g", "batt"])[1]
    m = re.search(r"(\d+)%", batt)
    if m and "AC Power" not in batt and int(m.group(1)) <= 20:
        if not MON["battery_warned"]:
            notify.send("battery", "Mac 電量剩 " + m.group(1) + "%", "請幫 Mac 插上電源，沒電後家裡的網路和雲端都會斷線", "/", urgent=True)
            MON["battery_warned"] = True
    elif "AC Power" in batt:
        MON["battery_warned"] = False
    # services
    for label, up in (("擋廣告 DNS", port_open(53)),) + ((("Shadowrocket (Xray)", port_open(10080)),) if settings.SHADOWROCKET else ()):
        was = MON["services"].get(label, True)
        if was and not up and _thr.ok("svc-" + label, 1800):
            notify.send("service", f"{label} 停止了", "系統會自動重新啟動，如果一直收到這個通知請檢查 Mac", "/#settings", urgent=True)
        MON["services"][label] = up
    # new devices + arrival (phone connected from the home Wi-Fi)
    st = ts_status()
    if st.get("ok"):
        ids = {p["id"]: p for p in st["peers"]}
        if MON["devices"] is not None:
            for pid in set(ids) - MON["devices"]:
                notify.send("device", "新裝置加入 VPN", f"{ids[pid]['name']}（{ids[pid]['os'] or '未知系統'}）", "/#settings")
        MON["devices"] = set(ids)
        prefs, lan = arrival_prefs(), lan_prefix()
        for pid, peer in ids.items():
            if not prefs.get(pid):
                continue
            home = bool(peer.get("online") and (peer.get("cur_addr") or "").startswith(lan))
            if home and MON["arrival"].get(pid) is False and _thr.ok("arr-" + pid, 1800):
                notify.send("arrival", f"{peer['name']} 回到家了", time.strftime("%H:%M") + " 連上家裡的 Wi-Fi", "/#settings")
            MON["arrival"][pid] = home
    # members: expiring tomorrow (once a day), time quota used up
    today = time.strftime("%Y-%m-%d")
    data = load_members()
    if MON["expiry_day"] != today and time.localtime().tm_hour >= 9:
        MON["expiry_day"] = today
        tomorrow = time.strftime("%Y-%m-%d", time.localtime(time.time() + 86400))
        for p in data["people"]:
            if p["expires"] == tomorrow:
                notify.send("member", f"{p['login']} 明天到期", "要延長的話，到「成員」裡改有效期限", "/#members")
    for p in data["people"]:
        if p["daily_min"] and USAGE["minutes"].get(p["login"], 0) >= p["daily_min"] and _thr.ok("quota-" + p["login"] + today, 86400):
            notify.send("member", f"{p['login']} 今天的時數用完了", f"已用 {p['daily_min']} 分鐘，明天 0 點會自動恢復", "/#members")
    # housekeeping
    if _thr.ok("trashpurge", 3600) and mounted:
        roots = [drive.SHARED_DIR, drive.USERS_DIR, BOX_DIR] + [os.path.join(drive.USERS_DIR, d) for d in os.listdir(drive.USERS_DIR)
                                                                  if os.path.isdir(os.path.join(drive.USERS_DIR, d))]
        drive.purge_old_trash(roots)
    bst = backup_state()
    if bst.get("enabled") and time.localtime().tm_hour == 3 and (not bst.get("last") or time.time() - bst["last"] > 20 * 3600):
        run_backup()


def speed_down(h, mb):
    n = max(1, min(50, int(mb or 10))) << 20
    h.send_response(200)
    h.send_header("Content-Type", "application/octet-stream")
    h.send_header("Content-Length", str(n))
    h.send_header("Cache-Control", "no-store")
    h.end_headers()
    chunk = os.urandom(1 << 16)
    sent = 0
    while sent < n:
        k = min(len(chunk), n - sent)
        h.wfile.write(chunk[:k])
        sent += k


def speed_up(h):
    n = min(int(h.headers.get("Content-Length", 0)), 100 << 20)
    t = time.time()
    left = n
    while left > 0:
        b = h.rfile.read(min(1 << 16, left))
        if not b:
            break
        left -= len(b)
    return {"ok": True, "bytes": n - left, "seconds": time.time() - t}


def safe(fn):
    try:
        return fn()
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    sys_version = ""

    def version_string(self):
        return "home"
    timeout = 120  # tailnet only; long enough for a phone pushing a big upload over a weak signal
    server_version = "HomePanel/1.0"

    def log_message(self, fmt, *args):
        pass

    def who(self):
        return self.headers.get("Tailscale-User-Name") or self.headers.get("Tailscale-User-Login") or "?"

    def cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def rp(self):
        """Passkeys are bound to the panel's own hostname, never to whatever Host header a request carries."""
        host = load_members().get("sr_host") or (self.headers.get("Host") or "").split(":")[0]
        return host, "https://" + host

    def from_tailscale(self):
        """Only `tailscale serve` may talk to the panel. Identity comes from a header, so a connection from any
        other local process (a proxy user tunnelling to 127.0.0.1, a script) could forge it — refuse those."""
        if getattr(self, "_peer_ok", None) is None:
            proc = peer_process(self.client_address[1])
            self._peer_ok = bool(proc and proc.startswith("io.tailscale"))
            if not self._peer_ok and self.headers.get("X-Selftest") == SELFTEST_TOKEN:
                return False
            if not self._peer_ok:
                log_event("安全", f"擋下不是經由 Tailscale 的連線（{proc or '未知程式'}）")
                security.record("spoof", proc or "未知程式", urllib.parse.urlparse(self.path).path[:60])
                if _thr.ok("peer-" + str(proc), 600):
                    notify.send("security", "擋下一個可疑連線", f"有程式（{proc or '未知'}）試圖冒用身分連進控制台，已經擋下", "/#settings", urgent=True)
        return self._peer_ok

    def authed(self, cap=None, owner_only=False):
        """Check identity and, for members, that they hold `cap`. Sets self.role/self.caps."""
        if not self.from_tailscale():
            self.send_json({"ok": False, "error": "只接受經由 Tailscale 的連線"}, 403)
            return False
        login = self.headers.get("Tailscale-User-Login")
        if not login:
            self.send_json({"ok": False, "error": "請透過 Tailscale 開啟這個頁面"}, 403)
            return False
        role, caps = member_role(login)
        if role is None:
            log_event("安全", f"拒絕存取：{login}（{caps}）")
            security.record("denied", None, caps, who=login)
            self.send_json({"ok": False, "error": caps}, 403)
            return False
        if (owner_only and role != "owner") or (cap and cap not in caps):
            self.send_json({"ok": False, "error": "你沒有這個功能的權限"}, 403)
            return False
        self.login, self.role, self.caps = login, role, caps
        path = urllib.parse.urlparse(self.path).path
        exempt = path in ("/", "/index.html", "/sw.js", "/manifest.json") or path.startswith("/static/") or path.startswith("/api/lock/")
        if not exempt and not applock.session_ok(login, self.cookie(applock.COOKIE), touch=True):
            self.send_json({"ok": False, "locked": True, "setup": not LOCK_STORE.get(login).get("pin"), "error": "已上鎖"}, 401)
            return False
        return True

    def same_origin(self):
        """Reject cross-site writes (CSRF): a browser always sends Origin on cross-origin POSTs."""
        origin = self.headers.get("Origin")
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return False
        if origin and urllib.parse.urlparse(origin).netloc != self.headers.get("Host"):
            return False
        return True

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def send_json(self, obj, code=200, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            if not self.authed():
                return
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path in ("/sw.js", "/manifest.json"):
            if not self.authed():
                return
            body = open(os.path.join(HERE, "static", u.path.lstrip("/")), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8" if u.path == "/sw.js" else "application/manifest+json")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path.startswith("/static/"):
            name = os.path.basename(u.path)
            path = os.path.join(HERE, "static", name)
            if not self.authed():
                return
            if not re.match(r"^[a-z0-9_.-]+\.(js|png)$", name) or not os.path.isfile(path):
                self.send_error(404)
                return
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png" if name.endswith(".png") else "text/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not u.path.startswith("/api/"):
            self.send_error(404)
            return
        need = {"/api/querylog": ("log", False), "/api/blocked_services": ("adblock", False),
                "/api/members": (None, True),
                "/api/proxy": (None, True)}.get(u.path, (None, False))
        if u.path.startswith("/api/drive/"):
            need = (None, True)
        if not self.authed(*need):
            return
        try:
            if u.path == "/api/overview":
                owner, caps = self.role == "owner", self.caps
                d = {"me": {"login": self.login, "name": self.headers.get("Tailscale-User-Name"),
                            "pic": self.headers.get("Tailscale-User-Profile-Pic"), "role": self.role, "caps": caps},
                     "time": time.time()}
                d["features"] = {"shadowrocket": settings.SHADOWROCKET}
                if "view" in caps:
                    d.update(system=safe(system_info), tailscale=safe(ts_status), adguard=safe(agh_overview))
                elif "adblock" in caps:
                    d.update(adguard=safe(agh_overview))
                if "remote" in caps:
                    pass  # music/volume are fetched on demand by the 遙控 tab (/api/media)
                if owner:
                    d.update(services=safe(services), events=list(EVENTS)[:30], kick=kick_status(), drive=drive.disk())
                self.send_json(d)
            elif u.path == "/api/querylog":
                mine = None if self.role == "owner" else member_device_ips(self.login)
                limit = min(int(q.get("limit", ["60"])[0] or 60), 200)
                params = {"limit": limit if mine is None else 1000, "search": q.get("search", [""])[0],
                          "response_status": q.get("status", ["all"])[0]}
                d = agh("querylog?" + urllib.parse.urlencode(params))
                rows = [{"time": r.get("time"), "domain": (r.get("question") or {}).get("name"),
                         "type": (r.get("question") or {}).get("type"), "client": r.get("client"),
                         "client_name": (r.get("client_info") or {}).get("name"), "reason": r.get("reason"),
                         "ms": r.get("elapsedMs"), "rule": ((r.get("rules") or [{}])[0]).get("text")}
                        for r in d.get("data") or [] if mine is None or r.get("client") in mine]
                self.send_json({"ok": True, "rows": rows[:limit]})
            elif u.path == "/api/blocked_services":
                allsvc = agh("blocked_services/all")
                cur = agh("blocked_services/get")
                self.send_json({"ok": True, "current": cur.get("ids") or [],
                                "services": [{"id": s["id"], "name": s["name"], "icon": s.get("icon_svg"),
                                              "group": s.get("group_id")} for s in allsvc.get("blocked_services", [])],
                                "groups": [{"id": g["id"]} for g in allsvc.get("groups", [])]})
            elif u.path == "/api/members":
                self.send_json(members_overview())
            elif u.path == "/api/proxy":
                self.send_json(proxy_info())
            elif u.path == "/api/lock/status":
                self.send_json({"ok": True, **applock.status(LOCK_STORE, self.login, self.cookie(applock.COOKIE)),
                                "idle_choices": applock.IDLE_CHOICES, "owner": self.role == "owner"})
            elif u.path == "/api/lock/reg-options":
                if not applock.session_ok(self.login, self.cookie(applock.COOKIE)):
                    self.send_json({"ok": False, "error": "請先用密碼解鎖"}, 401)
                else:
                    self.send_json({"ok": True, "options": applock.reg_options(LOCK_STORE, self.login, self.rp()[0])})
            elif u.path == "/api/lock/auth-options":
                try:
                    self.send_json({"ok": True, "options": applock.auth_options(LOCK_STORE, self.login, self.rp()[0])})
                except PermissionError as e:
                    self.send_json({"ok": False, "error": str(e)}, 400)
            elif u.path == "/api/notify":
                self.send_json({**notify.overview(), "log": notify.recent(60)} if self.role == "owner" else {"ok": False}, 200 if self.role == "owner" else 403)
            elif u.path == "/api/member_report":
                self.send_json(member_report(q.get("login", [""])[0]) if self.role == "owner" else {"ok": False, "error": "forbidden"})
            elif u.path == "/api/messages":
                self.send_json({"ok": True, "items": load_msgs(), "types": MSG_TYPES} if self.role == "owner" else {"ok": False})
            elif u.path == "/api/shares":
                self.send_json(share_list() if self.role == "owner" else {"ok": False})
            elif u.path == "/api/backup":
                self.send_json({"ok": True, **backup_state(), "dir": BACKUP_DIR.replace(HOME, "~"), "free": shutil.disk_usage(HOME).free} if self.role == "owner" else {"ok": False})
            elif u.path == "/api/mac":
                if "view" not in self.caps:
                    self.send_json({"ok": False, "error": "forbidden"}, 403)
                else:
                    d = cached("mac", 2, macstats.snapshot)
                    if q.get("hist", [""])[0] == "1":
                        d = {**d, "history": macstats.history()}
                    self.send_json(d)
            elif u.path == "/api/security":
                if self.role != "owner":
                    self.send_json({"ok": False, "error": "forbidden"}, 403)
                else:
                    self.send_json({"ok": True, **security.summary(), "checks": cached("sec-checks", 60, security_checks),
                                    "selftest": {k: _selftest[k] for k in ("running", "at", "results", "progress")}})
            elif u.path == "/api/arrival":
                self.send_json({"ok": True, "prefs": arrival_prefs()} if self.role == "owner" else {"ok": False})
            elif u.path == "/api/speed/down":
                speed_down(self, q.get("mb", ["10"])[0])
            elif u.path == "/api/media":
                if self.role != "owner" and "remote" not in self.caps:
                    self.send_json({"ok": False, "error": "forbidden"}, 403)
                else:
                    self.send_json({"ok": True, **cached("media", 3, lambda: {"media": safe(media_now), "volume": safe(get_volume)})})
            elif u.path == "/api/drive/usage":
                self.send_json(drive_usage())
            elif u.path == "/api/drive/stats":
                self.send_json(drive_stats())
            elif u.path == "/api/drive/summary":
                sc = owner_scope()
                self.send_json({"ok": True, "roots": {"ok": True, "mounted": drive.mounted(),
                                                      "roots": drive.roots_info(sc) if drive.mounted() else []},
                                "usage": drive_usage(), "stats": drive_stats()})
            elif u.path.startswith("/api/drive/"):
                drive_route(self, owner_scope(), u.path.rsplit("/", 1)[1], q, "GET", self.who())
            else:
                self.send_error(404)
        except Exception as e:
            self.send_json({"ok": False, "error": str(e)}, 500)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if not self.authed(owner_only=u.path.startswith("/api/drive/")):
            return
        if not self.same_origin():
            log_event("安全", f"擋下跨站請求：{self.headers.get('Origin')} → {u.path}")
            security.record("csrf", None, f"{self.headers.get('Origin')} → {u.path}", who=self.login)
            self.send_json({"ok": False, "error": "cross-site request blocked"}, 403)
            return
        ctype = self.headers.get("Content-Type") or ""
        is_upload = u.path in ("/api/drive/upload", "/api/speed/up")
        if is_upload and not self.headers.get("X-Filename"):
            self.send_json({"ok": False, "error": "missing filename"}, 400)
            return
        if not is_upload and not ctype.startswith("application/json"):
            self.send_json({"ok": False, "error": "json only"}, 415)
            return
        try:
            if u.path.startswith("/api/drive/"):
                drive_route(self, owner_scope(), u.path.rsplit("/", 1)[1], urllib.parse.parse_qs(u.query), "POST", self.who())
                return
            if u.path.startswith("/api/lock/"):
                self.lock_post(u.path.rsplit("/", 1)[1], self.read_json())
                return
            if u.path == "/api/push/subscribe":
                if self.role != "owner":
                    return self.send_json({"ok": False, "error": "只有管理員可以收通知"}, 403)
                body = self.read_json()
                notify.subscribe(body.get("subscription"), body.get("device"))
                log_event(self.who(), f"開啟推播通知（{body.get('device') or '裝置'}）")
                return self.send_json({"ok": True})
            if u.path == "/api/speed/up":
                return self.send_json(speed_up(self))
            if u.path == "/api/action":
                arg = self.read_json()
                name = arg.get("name")
                cap = ACTION_CAPS.get(name)
                if self.role != "owner" and (cap is None or cap not in self.caps):
                    self.send_json({"ok": False, "error": "你沒有這個功能的權限"}, 403)
                    return
                self.send_json(action(name, arg.get("arg") or {}, self.who()))
                return
            self.send_error(404)
        except Exception as e:
            self.send_json({"ok": False, "error": str(e)}, 500)

    def read_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_JSON:
            security.record("oversize", None, f"{n} bytes", who=getattr(self, "login", None))
            self.close_connection = True
            raise ValueError("資料太大")
        return json.loads(self.rfile.read(n) or b"{}")

    def lock_post(self, op, body):
        login, token = self.login, self.cookie(applock.COOKIE)
        rp_id, origin = self.rp()
        set_cookie = lambda t: {"Set-Cookie": f"{applock.COOKIE}={t}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={applock.ABSOLUTE_TTL}"}
        try:
            if op == "set-pin":
                first = not LOCK_STORE.get(login).get("pin")
                applock.set_pin(LOCK_STORE, login, str(body.get("pin", "")), token)
                log_event(login, "設定控制台密碼" if first else "更改控制台密碼")
                t = applock.new_session(LOCK_STORE, login)
                return self.send_json({"ok": True}, headers=set_cookie(t))
            if op == "pin":
                try:
                    t = applock.unlock_pin(LOCK_STORE, login, body.get("pin", ""))
                except PermissionError as e:
                    security.record("lock_fail", None, str(e), who=login)
                    if "鎖定" in str(e):
                        notify.send("security", "控制台密碼連續輸錯 5 次", f"{login} 的控制台已鎖定 15 分鐘", "/", urgent=True)
                    raise
                return self.send_json({"ok": True}, headers=set_cookie(t))
            if op == "passkey":
                t = applock.auth_finish(LOCK_STORE, login, rp_id, origin, body)
                return self.send_json({"ok": True}, headers=set_cookie(t))
            if op == "lock":
                applock.end_session(token)
                return self.send_json({"ok": True}, headers={"Set-Cookie": f"{applock.COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"})
            if op == "reset-self":
                # forgot PIN: the owner proves themselves with the kick password
                if self.role != "owner":
                    return self.send_json({"ok": False, "error": "請聯絡管理員重設"}, 403)
                err = check_kick_pw(body.get("password"), login)
                if err:
                    return self.send_json({"ok": False, "error": err}, 403)
                LOCK_STORE.drop(login)
                applock.end_all(login)
                log_event(login, "用踢人密碼重設了控制台密碼")
                return self.send_json({"ok": True})
            # everything below needs an unlocked session
            if not applock.session_ok(login, token, touch=True):
                return self.send_json({"ok": False, "locked": True, "error": "已上鎖"}, 401)
            if op == "passkey-register":
                applock.reg_finish(LOCK_STORE, login, rp_id, origin, body, body.get("device"))
                log_event(login, "啟用 Face ID 解鎖")
                return self.send_json({"ok": True})
            if op == "passkey-remove":
                applock.remove_passkeys(LOCK_STORE, login)
                log_event(login, "移除 Face ID 解鎖")
                return self.send_json({"ok": True})
            if op == "idle":
                applock.set_idle(LOCK_STORE, login, body.get("minutes"))
                return self.send_json({"ok": True})
            if op == "reset-member":
                if self.role != "owner":
                    return self.send_json({"ok": False, "error": "你沒有這個功能的權限"}, 403)
                target = str(body.get("login", ""))
                LOCK_STORE.drop(target)
                applock.end_all(target)
                log_event(login, f"重設 {target} 的控制台密碼")
                return self.send_json({"ok": True})
            self.send_json({"ok": False, "error": "unknown"}, 404)
        except (PermissionError, ValueError, KeyError) as e:
            self.send_json({"ok": False, "error": str(e) or "驗證失敗"}, 400)


if __name__ == "__main__":
    os.makedirs(BOX_DIR, exist_ok=True)
    log_event("系統", "控制台啟動")
    threading.Thread(target=policy_scheduler, daemon=True).start()
    threading.Thread(target=_io_monitor, daemon=True).start()
    _usage_load()

    def warm():  # fill slow caches before anyone opens the cloud tab
        try:
            disk_hw()
            if drive.mounted():
                for r in owner_scope().values():
                    if os.path.isdir(r.path):
                        drive.dir_size(r.path, wait=True)
                for p in load_members()["people"]:
                    if os.path.isdir(drive.user_dir(p["login"])):
                        drive.dir_size(drive.user_dir(p["login"]), wait=True)
                drive.dir_size(drive.DRIVE_ROOT, wait=True)
                _scan_kinds()
        except Exception:
            pass
    threading.Thread(target=warm, daemon=True).start()
    security.configure(on_ban=lambda ip, why: notify.send("security", "自動封鎖了一個可疑位址", f"{ip}：{why}，封鎖 24 小時", "/#settings", urgent=True))
    threading.Thread(target=BoundedServer((PORTAL_HOST, PORTAL_PORT), PortalHandler, limit=96).serve_forever, daemon=True).start()
    try:
        apply_xray("控制台啟動")
    except Exception as e:
        log_event("系統", f"⚠️ Shadowrocket 設定失敗：{e}")
    BoundedServer((HOST, PORT), Handler, limit=64).serve_forever()
