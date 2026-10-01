"""Detailed Mac health for the 'Mac' pane: battery, memory breakdown, network speed, thermal state, top programs,
plus a 24-hour history sampled once a minute. Everything here is cheap (ioreg / vm_stat / sysctl / netstat / ps),
so the Mac doesn't heat up; the slow hardware probe is cached for a day."""
import json
import os
import plistlib
import re
import subprocess
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
HIST_FILE = os.path.join(HERE, "mac-history.json")
HIST_LEN = 24 * 60  # one point per minute

_lock = threading.Lock()
_hist = deque(maxlen=HIST_LEN)
_net_prev = {}  # iface -> (t, rx, tx)
_hw = {"t": 0, "v": None}
_saved_at = 0


def _run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _sysctl(name):
    return _run(["sysctl", "-n", name]).strip()


# ---------- hardware (slow, cached for a day) ----------
def hardware():
    if _hw["v"] and time.time() - _hw["t"] < 86400:
        return _hw["v"]
    v = {}
    try:
        d = json.loads(_run(["system_profiler", "SPHardwareDataType", "-json"], 20))["SPHardwareDataType"][0]
        cores = re.findall(r"\d+", d.get("number_processors", ""))
        v = {"name": d.get("machine_name"), "chip": d.get("chip_type"), "memory": d.get("physical_memory"),
             "model": d.get("machine_model"),
             "cores": {"total": int(cores[0]), "perf": int(cores[1]), "eff": int(cores[2])} if len(cores) == 3 else None}
    except (ValueError, KeyError, IndexError):
        pass
    sw = dict(re.findall(r"^(\w+):\s*(.+)$", _run(["sw_vers"]), re.M))
    v["os"] = sw.get("ProductVersion")
    v["build"] = sw.get("BuildVersion")
    _hw.update(t=time.time(), v=v)
    return v


# ---------- battery ----------
def battery():
    raw = _run(["ioreg", "-rn", "AppleSmartBattery", "-a"]).encode()
    try:
        d = plistlib.loads(raw)[0]
    except Exception:
        return None
    design, maxcap = d.get("DesignCapacity") or 0, d.get("AppleRawMaxCapacity") or 0
    volt, amp = (d.get("Voltage") or 0) / 1000, (d.get("InstantAmperage") or d.get("Amperage") or 0)
    if amp > 2 ** 63:  # unsigned wrap for negative (discharging) current
        amp -= 2 ** 64
    tte, ttf = d.get("AvgTimeToEmpty"), d.get("AvgTimeToFull")
    return {
        "percent": d.get("CurrentCapacity"),
        "charging": bool(d.get("IsCharging")),
        "plugged": bool(d.get("ExternalConnected")),
        "full": bool(d.get("FullyCharged")),
        "health": round(maxcap / design * 100) if design and maxcap else None,
        "cycles": d.get("CycleCount"),
        "temp_c": round(d["Temperature"] / 100, 1) if d.get("Temperature") else None,
        "watts": round(volt * amp / 1000, 1),  # + charging, - draining
        "adapter_w": (d.get("AdapterDetails") or {}).get("Watts"),
        "minutes_left": tte if tte and tte < 65535 else None,
        "minutes_to_full": ttf if ttf and ttf < 65535 else None,
    }


# ---------- memory ----------
def memory():
    vm = _run(["vm_stat"])
    m = re.search(r"page size of (\d+)", vm)
    page = int(m.group(1)) if m else 16384
    p = {k.strip(): int(v) for k, v in re.findall(r"^(.+?):\s+(\d+)\.?$", vm, re.M)}
    total = int(_sysctl("hw.memsize") or 0)
    wired = p.get("Pages wired down", 0) * page
    compressed = p.get("Pages occupied by compressor", 0) * page
    purge = p.get("Pages purgeable", 0) * page
    app = max(0, p.get("Anonymous pages", 0) * page - purge)
    cached_files = p.get("File-backed pages", 0) * page + purge
    sw = re.findall(r"(total|used|free) = ([\d.]+)M", _sysctl("vm.swapusage"))
    swap = {k: float(v) * 1048576 for k, v in sw}
    level = int(_sysctl("kern.memorystatus_vm_pressure_level") or 1)
    return {"total": total, "app": app, "wired": wired, "compressed": compressed, "cached": cached_files,
            "used": app + wired + compressed, "free": max(0, total - app - wired - compressed - cached_files),
            "swap_used": swap.get("used", 0), "swap_total": swap.get("total", 0),
            "pressure": {1: "normal", 2: "warn", 4: "critical"}.get(level, "normal"),
            "free_pct": int(_sysctl("kern.memorystatus_level") or 0)}


# ---------- network ----------
def network():
    r = _run(["route", "-n", "get", "default"])
    iface = (re.search(r"interface: (\S+)", r) or [None, None])[1]
    gw = (re.search(r"gateway: (\S+)", r) or [None, None])[1]
    out = {"iface": iface, "gateway": gw, "ip": _run(["ipconfig", "getifaddr", iface]).strip() if iface else None,
           "wifi": None, "rx_rate": None, "tx_rate": None, "rx_total": None, "tx_total": None}
    if not iface:
        return out
    summ = _run(["ipconfig", "getsummary", iface])
    if "SSID" in summ or "IEEE80211" in summ or iface == "en0":
        ssid = (re.search(r"^\s+SSID : (.+)$", summ, re.M) or [None, None])[1]
        out["wifi"] = ssid if ssid and "redacted" not in ssid else "已連線"
    for line in _run(["netstat", "-ibn"]).splitlines():
        f = line.split()
        if len(f) >= 11 and f[0] == iface and f[2].startswith("<Link"):
            rx, tx, now = int(f[6]), int(f[9]), time.time()
            out["rx_total"], out["tx_total"] = rx, tx
            prev = _net_prev.get(iface)
            if prev and now - prev[0] >= 1:
                out["rx_rate"] = max(0, (rx - prev[1]) / (now - prev[0]))
                out["tx_rate"] = max(0, (tx - prev[2]) / (now - prev[0]))
            if not prev or now - prev[0] >= 1:
                _net_prev[iface] = (now, rx, tx)
            break
    return out


# ---------- programs ----------
def programs(n=8):
    procs = []
    for line in _run(["ps", "-Aceo", "pid=,pcpu=,rss=,comm="]).splitlines():
        f = line.split(None, 3)
        if len(f) == 4:
            try:
                procs.append({"pid": int(f[0]), "cpu": float(f[1]), "mem": int(f[2]) * 1024, "name": f[3]})
            except ValueError:
                pass
    ncpu = int(_sysctl("hw.ncpu") or 1)
    cpu = min(100.0, sum(p["cpu"] for p in procs) / ncpu)
    # one row per program: Chrome's dozens of helper processes add up into a single line with a count
    apps = {}
    for p in procs:
        a = apps.setdefault(p["name"], {"name": p["name"], "cpu": 0.0, "mem": 0, "n": 0})
        a["cpu"] += p["cpu"]
        a["mem"] += p["mem"]
        a["n"] += 1
    apps = [{**a, "cpu": round(a["cpu"], 1)} for a in apps.values()]
    return {"cpu": round(cpu, 1), "count": len(procs), "apps": len(apps),
            "by_cpu": sorted(apps, key=lambda p: -p["cpu"])[:n], "by_mem": sorted(apps, key=lambda p: -p["mem"])[:n]}


def thermal():
    t = _run(["pmset", "-g", "therm"])
    if re.search(r"No thermal warning level has been recorded", t) and "CPU_Speed_Limit" not in t:
        return {"state": "normal"}
    lim = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", t)
    lvl = re.search(r"thermal warning level.*?(\d+)", t, re.I)
    if lim and int(lim.group(1)) < 100:
        return {"state": "throttled", "speed_limit": int(lim.group(1))}
    return {"state": "warm" if lvl and int(lvl.group(1)) > 0 else "normal"}


# ---------- 24 h history ----------
def _load():
    try:
        with open(HIST_FILE) as f:
            pts = json.load(f)
        cut = time.time() - 86400
        _hist.extend(p for p in pts if p.get("t", 0) > cut)
    except (OSError, ValueError):
        pass


def _save():
    global _saved_at
    tmp = HIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(list(_hist), f, separators=(",", ":"))
    os.replace(tmp, HIST_FILE)
    _saved_at = time.time()


def record():
    """Called once a minute by the scheduler."""
    try:
        mem, net, pr, bat = memory(), network(), programs(1), battery()
        pt = {"t": int(time.time()), "cpu": pr["cpu"], "mem": round(mem["used"] / mem["total"] * 100, 1) if mem["total"] else None,
              "rx": round(net["rx_rate"] or 0), "tx": round(net["tx_rate"] or 0),
              "bat": bat["percent"] if bat else None, "temp": bat["temp_c"] if bat else None}
        with _lock:
            _hist.append(pt)
            if time.time() - _saved_at > 600:
                _save()
    except Exception:
        pass


def history():
    with _lock:
        return list(_hist)


def snapshot():
    pr = programs()
    up = re.search(r"sec = (\d+)", _sysctl("kern.boottime"))
    return {"ok": True, "t": time.time(), "hw": hardware(), "battery": battery(), "memory": memory(), "network": network(),
            "programs": pr, "cpu": pr["cpu"], "load": [float(x) for x in _sysctl("vm.loadavg").strip("{} ").split()[:3]],
            "uptime_s": int(time.time()) - int(up.group(1)) if up else None, "thermal": thermal()}


_load()
