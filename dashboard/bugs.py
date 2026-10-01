"""Bug tracker: reports from family members (member portal) and from the public GitHub repo, in one list.

Member reports live in bugs.json (screenshots re-encoded under bug-files/<id>/). GitHub issues are read and
answered through the `gh` CLI, which already holds the owner's login, so no token is stored here.
Everything shown in the panel is untrusted text (anyone can open a GitHub issue) — the UI escapes all of it."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BUG_FILE = os.path.join(HERE, "bugs.json")
FILE_DIR = os.path.join(HERE, "bug-files")
GH = shutil.which("gh") or "/opt/homebrew/bin/gh"
REPO = __import__("settings").GITHUB_REPO  # "owner/name" from config.json; empty turns GitHub off

STATUS = {"new": "新回報", "doing": "處理中", "fixed": "已修好", "wontfix": "不處理", "dup": "重複"}
OPEN_STATUS = ("new", "doing")
PRIORITY = {"low": "低", "mid": "中", "high": "高", "urgent": "緊急"}
AREA = {"cloud": "雲端硬碟", "net": "上網／連線", "sr": "Shadowrocket", "page": "專屬網頁", "other": "其他"}
SEVERITY = {"minor": "小問題", "annoying": "有點影響", "blocker": "完全不能用"}
MAX_SHOTS, MAX_PER_DAY = 3, 10

_lock = threading.Lock()
_ghc = {"at": 0, "items": [], "error": None, "known": None}  # cached issue list


def _load():
    try:
        with open(BUG_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _save(bugs):
    os.makedirs(os.path.dirname(BUG_FILE), exist_ok=True)
    tmp = BUG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(bugs, f, ensure_ascii=False)
    os.replace(tmp, BUG_FILE)


def _clean(text, n):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text or "")).strip()[:n]


def _find(bugs, bid):
    b = next((x for x in bugs if x["id"] == bid), None)
    if not b:
        raise ValueError("找不到這個回報")
    return b


# ---------------- member side ----------------
def report(login, body):
    title = _clean(body.get("title"), 80)
    if len(title) < 2:
        raise ValueError("請用一句話寫下發生什麼事")
    with _lock:
        bugs = _load()
        today = time.strftime("%Y-%m-%d")
        if sum(1 for b in bugs if b["by"] == login and time.strftime("%Y-%m-%d", time.localtime(b["at"])) == today) >= MAX_PER_DAY:
            raise ValueError("今天回報太多了，請明天再試")
        dev = body.get("device") or {}
        b = {"id": os.urandom(5).hex(), "by": login, "at": time.time(), "updated": time.time(), "title": title,
             "desc": _clean(body.get("desc"), 3000),
             "area": body.get("area") if body.get("area") in AREA else "other",
             "severity": body.get("severity") if body.get("severity") in SEVERITY else "minor",
             "device": {k: _clean(dev.get(k), 200) for k in ("ua", "screen", "page", "lang")} if body.get("device") else None,
             "status": "new", "priority": "", "note": "", "shots": [], "thread": [], "seen_by_member": True}
        bugs.insert(0, b)
        _save(bugs[:500])
    return b


def add_shot(login, bid, data):
    if len(data) > 8 << 20:
        raise ValueError("截圖太大（最多 8 MB）")
    with _lock:
        bugs = _load()
        b = _find(bugs, bid)
        if b["by"] != login:
            raise ValueError("找不到這個回報")
        if len(b["shots"]) >= MAX_SHOTS:
            raise ValueError(f"最多 {MAX_SHOTS} 張截圖")
        d = os.path.join(FILE_DIR, bid)
        os.makedirs(d, mode=0o700, exist_ok=True)
        n = len(b["shots"])
        with tempfile.TemporaryDirectory() as td:
            src, out = os.path.join(td, "in"), os.path.join(td, "out.jpg")
            with open(src, "wb") as f:
                f.write(data)
            r = subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "80", "-Z", "1600", src, "--out", out],
                               capture_output=True, timeout=30)
            if r.returncode != 0 or not os.path.exists(out):
                raise ValueError("看不懂這張圖片，請換一張（JPG／PNG／HEIC）")
            shutil.move(out, os.path.join(d, f"{n}.jpg"))
        b["shots"].append(n)
        b["updated"] = time.time()
        _save(bugs)
    return {"ok": True, "shots": len(b["shots"])}


def shot_path(bid, n):
    if not re.match(r"^[0-9a-f]{10}$", str(bid)) or not str(n).isdigit():
        return None
    p = os.path.join(FILE_DIR, bid, f"{int(n)}.jpg")
    return p if os.path.exists(p) else None


def mine(login):
    out = []
    for b in _load():
        if b["by"] == login:
            out.append({k: b[k] for k in ("id", "at", "updated", "title", "desc", "area", "severity", "status", "thread")} |
                       {"shots": len(b["shots"]), "unread": not b.get("seen_by_member", True)})
    return out[:30]


def member_reply(login, bid, text):
    text = _clean(text, 1000)
    if not text:
        raise ValueError("請寫點內容")
    with _lock:
        bugs = _load()
        b = _find(bugs, bid)
        if b["by"] != login:
            raise ValueError("找不到這個回報")
        b["thread"].append({"from": login, "t": time.time(), "text": text})
        if b["status"] in ("fixed", "wontfix"):
            b["status"] = "new"  # they say it still happens → back on your list
        b["updated"] = time.time()
        _save(bugs)
    return {"ok": True}


def mark_seen(login):
    with _lock:
        bugs = _load()
        changed = False
        for b in bugs:
            if b["by"] == login and not b.get("seen_by_member", True):
                b["seen_by_member"] = True
                changed = True
        if changed:
            _save(bugs)


# ---------------- owner side ----------------
def owner_update(bid, status=None, priority=None, note=None, reply=None):
    with _lock:
        bugs = _load()
        b = _find(bugs, bid)
        if status is not None:
            if status not in STATUS:
                raise ValueError("狀態不正確")
            b["status"] = status
        if priority is not None:
            if priority not in PRIORITY and priority != "":
                raise ValueError("優先度不正確")
            b["priority"] = priority
        if note is not None:
            b["note"] = _clean(note, 2000)
        if reply:
            b["thread"].append({"from": "owner", "t": time.time(), "text": _clean(reply, 2000)})
            b["seen_by_member"] = False
        b["updated"] = time.time()
        _save(bugs)
    return {"ok": True}


def owner_delete(bid):
    with _lock:
        bugs = _load()
        _find(bugs, bid)
        _save([b for b in bugs if b["id"] != bid])
    shutil.rmtree(os.path.join(FILE_DIR, bid), ignore_errors=True)
    return {"ok": True}


def all_member_bugs():
    return _load()


# ---------------- GitHub ----------------
def _gh(args, timeout=25):
    env = {**os.environ, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
    r = subprocess.run([GH, *args], capture_output=True, text=True, timeout=timeout, env=env)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:300] or "gh 執行失敗")
    return r.stdout


def gh_sync(on_new=None):
    """Refresh the GitHub issue list (called every 10 minutes and when the page asks)."""
    if not REPO:
        return
    try:
        items = json.loads(_gh(["issue", "list", "--repo", REPO, "--state", "all", "--limit", "100", "--json",
                                "number,title,state,stateReason,author,createdAt,updatedAt,labels,url,comments"]))
    except Exception as e:
        _ghc.update(error=str(e), at=time.time())
        return
    out = []
    for i in items:
        out.append({"number": i["number"], "title": i["title"], "state": i["state"], "reason": i.get("stateReason") or "",
                    "author": (i.get("author") or {}).get("login", "?"), "created": i["createdAt"], "updated": i["updatedAt"],
                    "labels": [l["name"] for l in i.get("labels") or []], "url": i["url"], "comments": len(i.get("comments") or [])})
    known = _ghc["known"]
    if known is not None and on_new:
        for i in out:
            if i["number"] not in known and i["state"] == "OPEN":
                on_new(i)
    _ghc.update(items=out, error=None, at=time.time(), known={i["number"] for i in out})


def gh_list(max_age=600):
    if not REPO:
        return {"items": [], "error": None, "at": 0, "repo": "", "off": True}
    if time.time() - _ghc["at"] > max_age:
        gh_sync()
    return {"items": _ghc["items"], "error": _ghc["error"], "at": _ghc["at"], "repo": REPO}


def gh_issue(number):
    d = json.loads(_gh(["issue", "view", str(int(number)), "--repo", REPO, "--json",
                        "number,title,body,state,stateReason,author,createdAt,labels,url,comments"]))
    return {"number": d["number"], "title": d["title"], "body": d.get("body") or "", "state": d["state"],
            "reason": d.get("stateReason") or "", "author": (d.get("author") or {}).get("login", "?"), "created": d["createdAt"],
            "labels": [l["name"] for l in d.get("labels") or []], "url": d["url"],
            "comments": [{"author": (c.get("author") or {}).get("login", "?"), "body": c.get("body") or "", "t": c.get("createdAt")}
                         for c in d.get("comments") or []]}


def gh_comment(number, text):
    text = _clean(text, 5000)
    if not text:
        raise ValueError("請寫點內容")
    _gh(["issue", "comment", str(int(number)), "--repo", REPO, "--body", text])
    _ghc["at"] = 0
    return {"ok": True}


def gh_set_state(number, state):
    n = str(int(number))
    if state == "fixed":
        _gh(["issue", "close", n, "--repo", REPO, "--reason", "completed"])
    elif state == "wontfix":
        _gh(["issue", "close", n, "--repo", REPO, "--reason", "not planned"])
    elif state == "reopen":
        _gh(["issue", "reopen", n, "--repo", REPO])
    else:
        raise ValueError("狀態不正確")
    _ghc["at"] = 0
    return {"ok": True}


def gh_label(number, label, on):
    if label not in ("bug", "enhancement", "question", "duplicate", "wontfix", "help wanted", "需要更多資訊"):
        raise ValueError("標籤不正確")
    _gh(["issue", "edit", str(int(number)), "--repo", REPO, "--add-label" if on else "--remove-label", label])
    _ghc["at"] = 0
    return {"ok": True}
