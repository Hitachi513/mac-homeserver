"""Notifications for the owner: an in-app log plus Web Push to installed home-screen apps (iOS 16.4+).

Web Push is standard RFC 8030/8291/8292: payloads are end-to-end encrypted (aes128gcm) so Apple's push service
never sees the text, and requests are signed with a VAPID key that lives only on this Mac.
"""
import base64
import json
import os
import threading
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import i18n

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "notify.json")   # VAPID key, subscriptions, prefs (mode 600)
LOG = os.path.join(HERE, "notify-log.json")  # recent notifications shown in the bell menu
SUBJECT = __import__("settings").CONTACT

# kind -> (label shown in settings, default on)
KINDS = {
    "security": ("安全警告（密碼輸錯、可疑連線）", True),
    "disk": ("硬碟（快滿、被拔掉、接回來）", True),
    "battery": ("Mac 電量過低", True),
    "service": ("服務停止（擋廣告、Shadowrocket）", True),
    "device": ("新裝置加入 VPN", True),
    "member": ("成員快到期、時數用完", True),
    "message": ("成員留言", True),
    "arrival": ("家人到家", True),
    "backup": ("雲端備份結果", True),
    "bug": ("問題回報（家人或 GitHub）", True),
}

_lock = threading.Lock()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save(path, data):
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(path + ".tmp", path)


def state():
    st = _load(STATE, {})
    if "vapid" not in st:
        key = ec.generate_private_key(ec.SECP256R1())
        st["vapid"] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
        _save(STATE, st)
    st.setdefault("subs", [])
    st.setdefault("prefs", {k: v[1] for k, v in KINDS.items()})
    return st


def _vapid_key(st):
    return serialization.load_pem_private_key(st["vapid"].encode(), None)


def public_key():
    pub = _vapid_key(state()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return b64u(pub)


def subscribe(sub, device, lang="zh-TW"):
    if not isinstance(sub, dict) or not str(sub.get("endpoint", "")).startswith("https://"):
        raise ValueError("訂閱資料不正確")
    keys = sub.get("keys") or {}
    if len(unb64u(keys.get("p256dh", ""))) != 65 or len(unb64u(keys.get("auth", ""))) != 16:
        raise ValueError("訂閱金鑰不正確")
    with _lock:
        st = state()
        st["subs"] = [s for s in st["subs"] if s["endpoint"] != sub["endpoint"]]
        st["subs"].append({"endpoint": sub["endpoint"], "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]},
                           "device": str(device or "裝置")[:40], "added": time.time(), "lang": lang})
        _save(STATE, st)


def set_lang(lang):
    """The owner switched language: later pushes follow."""
    with _lock:
        st = state()
        for s in st["subs"]:
            s["lang"] = lang
        _save(STATE, st)


def unsubscribe(endpoint=None):
    with _lock:
        st = state()
        st["subs"] = [s for s in st["subs"] if endpoint and s["endpoint"] != endpoint]
        _save(STATE, st)


def set_pref(kind, on):
    if kind not in KINDS:
        raise ValueError("unknown kind")
    with _lock:
        st = state()
        st["prefs"][kind] = bool(on)
        _save(STATE, st)


def _encrypt(payload, p256dh, auth):
    """RFC 8291 aes128gcm, one record."""
    ua_pub = unb64u(p256dh)
    auth = unb64u(auth)
    as_key = ec.generate_private_key(ec.SECP256R1())
    as_pub = as_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = as_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub))
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + ua_pub + as_pub).derive(shared)
    salt = os.urandom(16)
    # HKDF(salt).derive(ikm) = Expand(Extract(salt, ikm), info) — exactly the RFC's CEK / NONCE derivation
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    body = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + (4096).to_bytes(4, "big") + bytes([65]) + as_pub + body


def _vapid_header(st, endpoint):
    u = urllib.parse.urlparse(endpoint)
    head = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": SUBJECT},
                             separators=(",", ":")).encode())
    key = _vapid_key(st)
    r, s = decode_dss_signature(key.sign(f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256())))
    jwt = f"{head}.{claims}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return f"vapid t={jwt}, k={public_key()}"


def _push(st, sub, data):
    body = _encrypt(json.dumps(data, ensure_ascii=False).encode(), sub["keys"]["p256dh"], sub["keys"]["auth"])
    req = urllib.request.Request(sub["endpoint"], data=body, method="POST")
    req.add_header("Content-Encoding", "aes128gcm")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("TTL", "86400")
    req.add_header("Urgency", "high" if data.get("urgent") else "normal")
    req.add_header("Authorization", _vapid_header(st, sub["endpoint"]))
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def send(kind, title, body, url="/", urgent=False):
    """Log it, and push it to every subscribed device unless the owner muted this kind."""
    entry = {"t": time.time(), "kind": kind, "title": title, "body": body, "url": url, "read": False}
    with _lock:
        log = _load(LOG, [])
        log.insert(0, entry)
        _save(LOG, log[:200])
        st = state()
    if not st["prefs"].get(kind, True):
        return

    def work():
        dead = []
        for sub in st["subs"]:
            lang = sub.get("lang") or "zh-TW"  # each phone gets the notification in its own language
            code = _push(st, sub, {"title": i18n.t(title, lang), "body": i18n.t(body, lang), "url": url, "kind": kind, "urgent": urgent})
            if code in (404, 410):  # subscription gone (app deleted / permission revoked)
                dead.append(sub["endpoint"])
        if dead:
            with _lock:
                s2 = state()
                s2["subs"] = [s for s in s2["subs"] if s["endpoint"] not in dead]
                _save(STATE, s2)
    threading.Thread(target=work, daemon=True).start()


def recent(limit=50):
    return _load(LOG, [])[:limit]


def mark_read():
    with _lock:
        log = _load(LOG, [])
        for e in log:
            e["read"] = True
        _save(LOG, log)


def overview():
    st = state()
    return {"ok": True, "public_key": public_key(), "subs": [{"device": s["device"], "added": s["added"], "endpoint": s["endpoint"][-16:]}
                                                             for s in st["subs"]],
            "prefs": st["prefs"], "kinds": {k: v[0] for k, v in KINDS.items()},
            "unread": sum(1 for e in _load(LOG, []) if not e.get("read"))}


class Throttle:
    """Remember when each (kind, key) last fired so monitors don't spam."""

    def __init__(self):
        self.last = {}

    def ok(self, key, every):
        now = time.time()
        if now - self.last.get(key, 0) < every:
            return False
        self.last[key] = now
        return True
