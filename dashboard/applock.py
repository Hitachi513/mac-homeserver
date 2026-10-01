"""App lock for the panel: a 4-digit PIN and/or a passkey (Face ID / Touch ID via WebAuthn).

The lock is enforced server-side: until a person unlocks, the panel API answers 401 {"locked": true}.
An unlock sets an HttpOnly session cookie that expires after a period without activity.
Only ES256 passkeys are accepted (what iPhone / Mac passkeys use).
"""
import base64
import hashlib
import hmac
import json
import os
import threading
import time

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

COOKIE = "hp_unlock"
MAX_FAILS, LOCKOUT = 5, 900
ABSOLUTE_TTL = 12 * 3600
IDLE_CHOICES = (1, 5, 15, 60)

_lock = threading.Lock()
_sessions = {}      # token -> {"login", "seen", "created", "idle"}
_challenges = {}    # login -> (challenge bytes, expires, kind)
_fails = {}         # login -> {"n", "until"}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Store:
    """Lock records live in the panel's secrets file under "locks": {login: {...}}."""

    def __init__(self, load, save):
        self.load, self.save = load, save

    def get(self, login):
        return (self.load().get("locks") or {}).get(login) or {}

    def put(self, login, rec):
        sec = self.load()
        sec.setdefault("locks", {})[login] = rec
        self.save(sec)

    def drop(self, login):
        sec = self.load()
        (sec.get("locks") or {}).pop(login, None)
        self.save(sec)


def _hash_pin(pin, salt=None):
    salt = salt or os.urandom(16).hex()
    return {"salt": salt, "hash": hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()}


def status(store, login, cookie_token):
    rec = store.get(login)
    return {"has_pin": bool(rec.get("pin")), "passkeys": len(rec.get("creds") or []),
            "idle_min": rec.get("idle_min", 5), "unlocked": session_ok(login, cookie_token),
            "locked_until": (_fails.get(login) or {}).get("until") if (_fails.get(login) or {}).get("until", 0) > time.time() else None}


# ---------- sessions ----------

def new_session(store, login):
    token = os.urandom(24).hex()
    idle = store.get(login).get("idle_min", 5) * 60
    with _lock:
        _sessions[token] = {"login": login, "seen": time.time(), "created": time.time(), "idle": idle}
    return token


def session_ok(login, token, touch=False):
    if not token:
        return False
    with _lock:
        s = _sessions.get(token)
        now = time.time()
        if not s or s["login"] != login or now - s["seen"] > s["idle"] or now - s["created"] > ABSOLUTE_TTL:
            if s:
                _sessions.pop(token, None)
            return False
        if touch:
            s["seen"] = now
        return True


def end_session(token):
    with _lock:
        _sessions.pop(token, None)


def end_all(login):
    with _lock:
        for t in [t for t, s in _sessions.items() if s["login"] == login]:
            _sessions.pop(t, None)


# ---------- PIN ----------

def _throttled(login):
    f = _fails.get(login) or {}
    if f.get("until", 0) > time.time():
        return f"輸錯太多次，請 {int(f['until'] - time.time()) // 60 + 1} 分鐘後再試"
    return None


def _fail(login):
    f = _fails.setdefault(login, {"n": 0, "until": 0})
    f["n"] += 1
    if f["n"] >= MAX_FAILS:
        f.update(n=0, until=time.time() + LOCKOUT)
        return "輸錯太多次，鎖定 15 分鐘"
    return f"密碼錯誤（還剩 {MAX_FAILS - f['n']} 次）"


def set_pin(store, login, pin, current_token):
    """First-time setup needs nothing; changing an existing PIN needs an unlocked session."""
    if not (isinstance(pin, str) and len(pin) == 4 and pin.isdigit()):
        raise ValueError("密碼要是 4 位數字")
    rec = store.get(login)
    if rec.get("pin") and not session_ok(login, current_token):
        raise PermissionError("請先解鎖")
    rec["pin"] = _hash_pin(pin)
    store.put(login, rec)


def unlock_pin(store, login, pin):
    err = _throttled(login)
    if err:
        raise PermissionError(err)
    rec = store.get(login).get("pin")
    if not rec:
        raise PermissionError("還沒設定密碼")
    if hmac.compare_digest(_hash_pin(str(pin), rec["salt"])["hash"], rec["hash"]):
        _fails.pop(login, None)
        return new_session(store, login)
    raise PermissionError(_fail(login))


def set_idle(store, login, minutes):
    if int(minutes) not in IDLE_CHOICES:
        raise ValueError("不支援的時間")
    rec = store.get(login)
    rec["idle_min"] = int(minutes)
    store.put(login, rec)


# ---------- passkeys (WebAuthn, ES256 only) ----------

def _challenge(login, kind):
    c = os.urandom(32)
    _challenges[login] = (c, time.time() + 120, kind)
    return b64u(c)


def _take_challenge(login, kind):
    c = _challenges.pop(login, None)
    if not c or c[1] < time.time() or c[2] != kind:
        raise PermissionError("驗證逾時，請再試一次")
    return c[0]


def _check_client_data(raw, kind, challenge, origin):
    cd = json.loads(raw)
    if cd.get("type") != kind:
        raise PermissionError("驗證資料不正確")
    if not hmac.compare_digest(unb64u(cd.get("challenge", "")), challenge):
        raise PermissionError("驗證資料不正確")
    if cd.get("origin") != origin:
        raise PermissionError("來源網址不正確")


def _check_auth_data(ad, rp_id):
    if len(ad) < 37 or ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise PermissionError("網域不正確")
    flags = ad[32]
    if not (flags & 0x01 and flags & 0x04):  # user present + user verified (Face ID / passcode)
        raise PermissionError("需要 Face ID 驗證")
    return flags


def reg_options(store, login, rp_id):
    rec = store.get(login)
    return {"challenge": _challenge(login, "create"), "rp": {"id": rp_id, "name": "家用控制台"},
            "user": {"id": b64u(hashlib.sha256(login.encode()).digest()[:16]), "name": login, "displayName": login},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"authenticatorAttachment": "platform", "userVerification": "required",
                                       "residentKey": "preferred"},
            "excludeCredentials": [{"type": "public-key", "id": c["id"]} for c in rec.get("creds") or []],
            "attestation": "none", "timeout": 60000}


def reg_finish(store, login, rp_id, origin, body, device_name):
    challenge = _take_challenge(login, "create")
    client_data = unb64u(body["clientDataJSON"])
    _check_client_data(client_data, "webauthn.create", challenge, origin)
    att = cbor2.loads(unb64u(body["attestationObject"]))
    ad = att["authData"]
    flags = _check_auth_data(ad, rp_id)
    if not flags & 0x40:
        raise PermissionError("沒有收到金鑰")
    cred_len = int.from_bytes(ad[53:55], "big")
    cred_id = ad[55:55 + cred_len]
    cose = cbor2.loads(ad[55 + cred_len:])
    if cose.get(3) != -7 or cose.get(-1) != 1:
        raise PermissionError("只支援 Face ID / Touch ID 的通行密鑰")
    x, y = cose[-2], cose[-3]
    ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    rec = store.get(login)
    creds = [c for c in rec.get("creds") or [] if c["id"] != b64u(cred_id)]
    creds.append({"id": b64u(cred_id), "x": b64u(x), "y": b64u(y), "name": str(device_name or "iPhone")[:40],
                  "added": time.time()})
    rec["creds"] = creds
    store.put(login, rec)


def auth_options(store, login, rp_id):
    creds = store.get(login).get("creds") or []
    if not creds:
        raise PermissionError("還沒啟用 Face ID")
    return {"challenge": _challenge(login, "get"), "rpId": rp_id, "userVerification": "required", "timeout": 60000,
            "allowCredentials": [{"type": "public-key", "id": c["id"], "transports": ["internal", "hybrid"]} for c in creds]}


def auth_finish(store, login, rp_id, origin, body):
    err = _throttled(login)
    if err:
        raise PermissionError(err)
    challenge = _take_challenge(login, "get")
    cred = next((c for c in store.get(login).get("creds") or [] if c["id"] == body.get("id")), None)
    if not cred:
        raise PermissionError("這個通行密鑰沒有註冊")
    client_data = unb64u(body["clientDataJSON"])
    _check_client_data(client_data, "webauthn.get", challenge, origin)
    ad = unb64u(body["authenticatorData"])
    _check_auth_data(ad, rp_id)
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(cred["x"]), "big"), int.from_bytes(unb64u(cred["y"]), "big"),
                                        ec.SECP256R1()).public_key()
    try:
        key.verify(unb64u(body["signature"]), ad + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise PermissionError(_fail(login))
    _fails.pop(login, None)
    return new_session(store, login)


def remove_passkeys(store, login):
    rec = store.get(login)
    rec["creds"] = []
    store.put(login, rec)
