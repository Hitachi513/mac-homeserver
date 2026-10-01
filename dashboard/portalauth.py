"""Member portal extras: an optional password on top of the secret link, and a personal profile (nickname + avatar).

Stored apart from members.json (which the owner's editor rewrites wholesale):
  portal-auth.json  {"secret": hex, "people": {login: {"pw": {salt, hash, iters}, "ver": n, "key": hex}}}   mode 600
  profiles.json     {login: {"nickname": str, "emoji": str, "color": "#rrggbb"}}
  avatars/<sha1(login)>.jpg   uploaded photo, re-encoded to 256 px JPEG (drops any metadata)
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = os.path.join(HERE, "portal-auth.json")
PROFILE_FILE = os.path.join(HERE, "profiles.json")
AVATAR_DIR = os.path.join(HERE, "avatars")
SESSION_DAYS = 30
MAX_FAILS, LOCK_SECONDS = 5, 900
EMOJIS = ["😀", "😎", "🥰", "🤓", "🐱", "🐶", "🦊", "🐼", "🐨", "🦁", "🐯", "🐸", "🐵", "🐧", "🦄", "🐳",
          "🌸", "🌻", "⭐️", "🍀", "🍓", "🍩", "⚽️", "🎮", "🎧", "🚀", "🌈", "🔥"]
COLORS = ["#5e5ce6", "#0a84ff", "#32ade6", "#30d158", "#ff9f0a", "#ff375f", "#bf5af2", "#8e8e93"]

_lock = threading.Lock()
_fails = {}   # login -> [timestamps]


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def _auth():
    a = _load(AUTH_FILE, {})
    if not a.get("secret"):
        a["secret"] = os.urandom(32).hex()
        a.setdefault("people", {})
        _save(AUTH_FILE, a)
    a.setdefault("people", {})
    return a


def _hash(pw, salt=None, iters=200_000):
    salt = salt or os.urandom(16).hex()
    return {"salt": salt, "iters": iters, "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), iters).hex()}


# ---------------- password ----------------
def has_password(login):
    return bool(_auth()["people"].get(login, {}).get("pw"))


def set_password(login, pw):
    """Owner sets (or member changes) the password; every existing session is signed out."""
    pw = str(pw or "")
    if len(pw) < 4 or len(pw) > 64:
        raise ValueError("密碼要 4 到 64 個字")
    with _lock:
        a = _auth()
        rec = a["people"].setdefault(login, {})
        rec["pw"] = _hash(pw)
        rec["ver"] = int(rec.get("ver", 0)) + 1
        _save(AUTH_FILE, a)
    _fails.pop(login, None)


def clear_password(login):
    with _lock:
        a = _auth()
        rec = a["people"].setdefault(login, {})
        rec.pop("pw", None)
        rec["ver"] = int(rec.get("ver", 0)) + 1
        _save(AUTH_FILE, a)


def check_password(login, pw):
    """Returns None on success, else an error message. Five wrong tries lock the page for 15 minutes."""
    now = time.time()
    tries = [t for t in _fails.get(login, []) if now - t < LOCK_SECONDS]
    if len(tries) >= MAX_FAILS:
        return f"密碼錯太多次，請 {int((LOCK_SECONDS - (now - tries[0])) // 60) + 1} 分鐘後再試"
    rec = _auth()["people"].get(login, {})
    if rec.get("pw") and hmac.compare_digest(_hash(str(pw or ""), rec["pw"]["salt"], rec["pw"]["iters"])["hash"], rec["pw"]["hash"]):
        _fails.pop(login, None)
        return None
    tries.append(now)
    _fails[login] = tries
    left = MAX_FAILS - len(tries)
    return f"密碼錯誤（還可以試 {left} 次）" if left else "密碼錯太多次，鎖定 15 分鐘"


def session_value(login):
    a = _auth()
    ver = a["people"].get(login, {}).get("ver", 0)
    return hmac.new(bytes.fromhex(a["secret"]), f"{login}|{ver}".encode(), "sha256").hexdigest()


def session_ok(login, cookie_value):
    return bool(cookie_value) and hmac.compare_digest(session_value(login), cookie_value)


# ---------------- photo-backup key (Shortcuts can't log in) ----------------
def backup_key(login):
    with _lock:
        a = _auth()
        rec = a["people"].setdefault(login, {})
        if not rec.get("key"):
            rec["key"] = os.urandom(16).hex()
            _save(AUTH_FILE, a)
        return rec["key"]


def backup_key_ok(login, key):
    rec = _auth()["people"].get(login, {})
    return bool(key and rec.get("key")) and hmac.compare_digest(rec["key"], str(key))


# ---------------- profile ----------------
def avatar_path(login):
    return os.path.join(AVATAR_DIR, hashlib.sha1(login.encode()).hexdigest() + ".jpg")


def profile(login):
    pr = _load(PROFILE_FILE, {}).get(login, {})
    has_img = os.path.exists(avatar_path(login))
    return {"nickname": pr.get("nickname", ""), "emoji": pr.get("emoji", ""), "color": pr.get("color", COLORS[0]),
            "photo": has_img, "v": int(os.path.getmtime(avatar_path(login))) if has_img else 0}


def set_profile(login, nickname=None, emoji=None, color=None, remove_photo=False):
    with _lock:
        allp = _load(PROFILE_FILE, {})
        pr = allp.setdefault(login, {})
        if nickname is not None:
            nickname = re.sub(r"[\x00-\x1f<>]", "", str(nickname)).strip()[:20]
            pr["nickname"] = nickname
        if emoji is not None:
            if emoji not in EMOJIS and emoji != "":
                raise ValueError("不支援這個頭像")
            pr["emoji"] = emoji
        if color is not None:
            if color not in COLORS:
                raise ValueError("不支援這個顏色")
            pr["color"] = color
        _save(PROFILE_FILE, allp)
    if remove_photo:
        try:
            os.remove(avatar_path(login))
        except FileNotFoundError:
            pass
    return profile(login)


def save_photo(login, data):
    """Re-encode whatever was uploaded into a 256 px JPEG with sips; anything sips can't read is rejected."""
    if len(data) > 8 << 20:
        raise ValueError("照片太大（最多 8 MB）")
    os.makedirs(AVATAR_DIR, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        src, out = os.path.join(td, "in"), os.path.join(td, "out.jpg")
        with open(src, "wb") as f:
            f.write(data)
        r = subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "85", "-Z", "512", src, "--out", out],
                           capture_output=True, timeout=30)
        if r.returncode != 0 or not os.path.exists(out):
            raise ValueError("看不懂這張照片，請換一張（JPG／PNG／HEIC）")
        # square crop from the centre, then 256 px
        dims = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", out], capture_output=True, text=True).stdout
        w, h = (int(x) for x in re.findall(r"pixel(?:Width|Height): (\d+)", dims)[:2])
        side = min(w, h)
        subprocess.run(["sips", "-c", str(side), str(side), out], capture_output=True, timeout=30)
        subprocess.run(["sips", "-Z", "256", out], capture_output=True, timeout=30)
        shutil.move(out, avatar_path(login))
    return profile(login)
