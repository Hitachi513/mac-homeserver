"""Home cloud drive on the external disk: scoped file operations shared by the owner panel and the member portal.

A *scope* maps virtual top-level folders (what the user sees) to real directories plus a write flag:
    {"mine": Root(path, writable=True, label="我的檔案", quota=5 GB, usage_key="alice"), ...}
Every path from a client is resolved inside one root and re-checked after realpath, so "..", absolute paths and
symlinks can never escape it.
"""
import mimetypes
import os
import re
import shutil
import threading
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass

import settings

DRIVE_ROOT = settings.DRIVE_ROOT
USERS_DIR = os.path.join(DRIVE_ROOT, "users")
SHARED_DIR = os.path.join(DRIVE_ROOT, "shared")
HIDDEN = {"$RECYCLE.BIN", "System Volume Information", ".Spotlight-V100", ".fseventsd", ".Trashes", ".TemporaryItems"}
BAD_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')  # not allowed on exFAT
# Only formats a browser renders without running code may be shown inline; everything else (SVG, HTML, ...) downloads.
PREVIEW = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/heic", "image/heif", "image/avif", "image/bmp",
           "video/mp4", "video/quicktime", "video/webm", "video/x-m4v", "audio/mpeg", "audio/mp4", "audio/x-m4a",
           "audio/aac", "audio/wav", "audio/x-wav", "audio/flac", "application/pdf", "text/plain"}

TEXT_EXT = {"txt", "md", "markdown", "csv", "tsv", "json", "log", "srt", "vtt", "xml", "yml", "yaml", "ini", "conf", "toml",
            "py", "js", "ts", "jsx", "tsx", "html", "htm", "css", "sh", "zsh", "bat", "c", "h", "cpp", "java", "go", "rs",
            "swift", "kt", "rb", "php", "sql", "lua", "r", "m", "tex"}
# Quick Look renders these on the Mac, so we can show a picture of the first page
OFFICE_EXT = {"doc", "docx", "rtf", "odt", "pages", "xls", "xlsx", "ods", "numbers", "ppt", "pptx", "odp", "key"}
TEXTUTIL_EXT = {"doc", "docx", "rtf", "odt"}
TYPE_LABEL = {"folder": "資料夾", "image": "照片", "video": "影片", "audio": "音樂 / 錄音", "pdf": "PDF 文件",
              "doc": "文件", "text": "文字檔", "archive": "壓縮檔", "file": "檔案"}

_size_cache = {}


# ---- exFAT + macOS: names come back from listdir decomposed (NFD), but unlink/rmdir only accept the composed (NFC) form,
# so "café.txt", "が.txt" or Korean names could not be deleted. Show NFC everywhere and delete through these helpers.
def nfc(name):
    return unicodedata.normalize("NFC", name)


def _rm(fn, path):
    try:
        fn(nfc(path))
    except FileNotFoundError:
        fn(path)


def remove(path):
    _rm(os.unlink, path)


def rmtree(path, ignore_errors=False):
    try:
        for dp, dns, fns in os.walk(path, topdown=False):
            for f in fns:
                remove(os.path.join(dp, f))
            for d in dns:
                full = os.path.join(dp, d)
                _rm(os.unlink if os.path.islink(full) else os.rmdir, full)
        _rm(os.rmdir, path)
    except OSError:
        if not ignore_errors:
            raise


class DriveError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


@dataclass
class Root:
    path: str
    writable: bool
    label: str
    quota: int = 0          # bytes, 0 = unlimited
    usage_key: str = ""     # whose usage counts against the quota
    desc: str = ""          # one-line explanation shown under the folder


def mounted():
    return os.path.isdir(DRIVE_ROOT)


def user_dir(login):
    safe = BAD_CHARS.sub("_", login).strip(". ") or "_"
    return os.path.join(USERS_DIR, safe)


def clean_name(name):
    name = BAD_CHARS.sub("_", str(name or "")).strip()
    if not name or name in (".", "..") or name.startswith(".") or name in HIDDEN or len(name) > 200:
        raise DriveError("檔名不合法")
    return name


_refreshing = set()


def _walk_size(path):
    total = 0
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in HIDDEN]
        for f in fns:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    _size_cache[path] = (time.time(), total)
    return total


def dir_size(path, ttl=60, wait=False):
    """Total bytes under path. Walking a big folder on USB is slow, so a stale value is returned right away and
    refreshed in the background; only the very first call (or wait=True) walks synchronously."""
    hit = _size_cache.get(path)
    if hit and (time.time() - hit[0] < ttl or not wait):
        if time.time() - hit[0] >= ttl and path not in _refreshing:
            _refreshing.add(path)
            def bg():
                try:
                    _walk_size(path)
                finally:
                    _refreshing.discard(path)
            threading.Thread(target=bg, daemon=True).start()
        return hit[1]
    return _walk_size(path)


def invalidate(path):
    """After a write: recompute affected folder sizes in the background (keep serving the old numbers meanwhile)."""
    for k in list(_size_cache):
        if path.startswith(k) or k.startswith(path):
            t, v = _size_cache[k]
            _size_cache[k] = (0, v)
            dir_size(k)


def disk():
    if not mounted():
        return None
    du = shutil.disk_usage(DRIVE_ROOT)
    return {"total": du.total, "used": du.total - du.free, "free": du.free}


def resolve(scope, vpath, must_exist=True):
    """'/mine/photos/a.jpg' -> (root, absolute path). Raises on anything outside the root."""
    if not mounted():
        raise DriveError("外接硬碟沒有接上", 503)
    parts = [p for p in str(vpath or "").split("/") if p]
    if not parts or parts[0] not in scope:
        raise DriveError("找不到這個位置", 404)
    root = scope[parts[0]]
    os.makedirs(root.path, exist_ok=True)
    for p in parts[1:]:
        if p in (".", "..") or p.startswith(".") or p in HIDDEN:
            raise DriveError("找不到這個位置", 404)
    target = os.path.join(root.path, *parts[1:])
    real_root = os.path.realpath(root.path)
    real = os.path.realpath(target)
    if real != real_root and not real.startswith(real_root + os.sep):
        raise DriveError("找不到這個位置", 404)
    if os.path.islink(target):
        raise DriveError("找不到這個位置", 404)
    if must_exist and not os.path.exists(real):
        raise DriveError("找不到這個位置", 404)
    return root, real


def kind(name, is_dir):
    if is_dir:
        return "folder"
    mt = mimetypes.guess_type(name)[0] or ""
    for k in ("image", "video", "audio"):
        if mt.startswith(k + "/"):
            return k
    if mt == "application/pdf":
        return "pdf"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in ("zip", "rar", "7z", "gz", "tar", "dmg"):
        return "archive"
    if ext in TEXT_EXT:
        return "text"
    if ext in OFFICE_EXT:
        return "doc"
    if ext in ("heic", "heif"):
        return "image"
    return "file"


def roots_info(scope):
    out = []
    for key, r in scope.items():
        used = dir_size(r.path) if mounted() and os.path.isdir(r.path) else 0
        out.append({"key": key, "label": r.label, "desc": r.desc, "writable": r.writable, "quota": r.quota, "used": used})
    return out


def list_dir(scope, vpath):
    root, real = resolve(scope, vpath)
    if not os.path.isdir(real):
        raise DriveError("這不是資料夾")
    items = []
    with os.scandir(real) as it:
        for e in it:
            if e.name.startswith(".") or e.name in HIDDEN or e.is_symlink():
                continue
            try:
                st = e.stat()
            except OSError:
                continue
            is_dir = e.is_dir()
            items.append({"name": nfc(e.name), "dir": is_dir, "size": 0 if is_dir else st.st_size,
                          "mtime": st.st_mtime, "ctime": _born(st), "kind": kind(e.name, is_dir)})
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return {"ok": True, "path": "/" + "/".join(p for p in vpath.split("/") if p), "writable": root.writable,
            "items": items, "root": {"label": root.label, "quota": root.quota,
                                     "used": dir_size(root.path) if root.quota else None}}


def _born(st):
    """When the file was created here (= uploaded); exFAT keeps a creation time and macOS exposes it."""
    return getattr(st, "st_birthtime", None) or st.st_mtime


def info(scope, vpath):
    """Details sheet: type, times, size; folders get a recursive count, photos their pixel size."""
    root, real = resolve(scope, vpath)
    st = os.stat(real)
    name = os.path.basename(real)
    is_dir = os.path.isdir(real)
    k = kind(name, is_dir)
    out = {"ok": True, "name": name, "kind": k, "type": TYPE_LABEL.get(k, "檔案"), "dir": is_dir,
           "ext": name.rsplit(".", 1)[-1].upper() if "." in name and not is_dir else "",
           "ctime": _born(st), "mtime": st.st_mtime, "size": st.st_size, "writable": root.writable}
    if is_dir:
        files = dirs = total = 0
        t0 = time.time()
        for dp, dns, fns in os.walk(real):
            dns[:] = [d for d in dns if not d.startswith(".") and d not in HIDDEN]
            dirs += len(dns)
            for f in fns:
                if f.startswith("."):
                    continue
                files += 1
                try:
                    total += os.lstat(os.path.join(dp, f)).st_size
                except OSError:
                    pass
            if time.time() - t0 > 8:
                out["partial"] = True
                break
        out.update(files=files, dirs=dirs, size=total)
    elif k == "image":
        r = subprocess.run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", real], capture_output=True, text=True, timeout=15)
        m = re.findall(r"pixel(Width|Height): (\d+)", r.stdout)
        if len(m) == 2:
            out["dims"] = [int(dict(m)["Width"]), int(dict(m)["Height"])]
    return out


def text_preview(scope, vpath, limit=256 << 10):
    """First 256 KB of a text/code file (or the text inside a Word/RTF file) as a string, never as HTML."""
    _, real = resolve(scope, vpath)
    if not os.path.isfile(real):
        raise DriveError("這不是檔案")
    ext = real.rsplit(".", 1)[-1].lower() if "." in os.path.basename(real) else ""
    if ext in TEXTUTIL_EXT:
        r = subprocess.run(["textutil", "-convert", "txt", "-stdout", real], capture_output=True, timeout=30)
        raw = r.stdout
        if r.returncode != 0:
            raise DriveError("無法讀取這個文件", 415)
    elif ext in TEXT_EXT or kind(real, False) == "text":
        with open(real, "rb") as f:
            raw = f.read(limit + 1)
    else:
        raise DriveError("這種檔案不能用文字預覽", 415)
    cut = len(raw) > limit
    raw = raw[:limit]
    for enc in ("utf-8-sig", "utf-16", "cp950", "gb18030"):
        if enc == "utf-16" and not raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            continue
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            if enc == "utf-8-sig" and cut:  # we may have cut a multi-byte character in half
                try:
                    text = raw[:-3].decode(enc)
                    break
                except UnicodeDecodeError:
                    pass
    else:
        text, enc = raw.decode("latin-1"), "latin-1"
    if "\x00" in text[:4096]:
        raise DriveError("這看起來不是文字檔", 415)
    return {"ok": True, "text": text, "truncated": cut, "ext": ext, "size": os.path.getsize(real)}


def move(scope, paths, dest):
    """Move files/folders into dest (another folder, possibly in another root), checking write access and quota."""
    droot, dreal = resolve(scope, dest)
    _need_write(droot)
    if not os.path.isdir(dreal):
        raise DriveError("目的地不是資料夾")
    moved, touched = 0, {droot.path}
    for vp in paths:
        root, real = resolve(scope, vp)
        _need_write(root)
        if real == os.path.realpath(root.path):
            raise DriveError("不能移動最上層資料夾")
        if os.path.dirname(real) == dreal:
            continue
        if dreal == real or dreal.startswith(real + os.sep):
            raise DriveError("不能把資料夾移到它自己裡面")
        if droot.path != root.path and droot.quota:
            size = _walk_size(real) if os.path.isdir(real) else os.path.getsize(real)
            if dir_size(droot.path, ttl=5, wait=True) + size > droot.quota:
                raise DriveError("目的地的容量不夠", 413)
        name = os.path.basename(real)
        base, ext = os.path.splitext(name) if not os.path.isdir(real) else (name, "")
        target, n = os.path.join(dreal, name), 1
        while os.path.exists(target):
            target = os.path.join(dreal, f"{base} ({n}){ext}")
            n += 1
        try:
            os.rename(real, target)
        except OSError:  # different disk (Mac 傳輸箱 <-> external drive): copy, then delete with the exFAT-safe helpers
            if os.path.isdir(real):
                shutil.copytree(real, target)
                rmtree(real)
            else:
                shutil.copy2(real, target)
                remove(real)
        touched.add(root.path)
        moved += 1
    for p in touched:
        invalidate(p)
    return {"ok": True, "moved": moved}


def send_zip(handler, scope, vpath):
    """Stream a folder as a .zip (no compression: photos/videos don't shrink and it keeps the Mac cool)."""
    import zipfile
    _, real = resolve(scope, vpath)
    if not os.path.isdir(real):
        raise DriveError("這不是資料夾")
    name = os.path.basename(real) or "雲端"

    class Out:  # zipfile needs a file-like object; this one just writes to the socket and counts bytes
        def __init__(self):
            self.n = 0

        def write(self, b):
            handler.wfile.write(b)
            self.n += len(b)
            return len(b)

        def tell(self):
            return self.n

        def flush(self):
            pass

    handler.send_response(200)
    handler.send_header("Content-Type", "application/zip")
    handler.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(name + ".zip"))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.close_connection = True
    with zipfile.ZipFile(Out(), "w", zipfile.ZIP_STORED, allowZip64=True) as z:
        for dp, dns, fns in os.walk(real):
            dns[:] = sorted(d for d in dns if not d.startswith(".") and d not in HIDDEN)
            if not dns and not any(not f.startswith(".") for f in fns):  # keep empty folders
                z.writestr(os.path.join(name, os.path.relpath(dp, real)).rstrip("/.") + "/", b"")
            for f in sorted(fns):
                if f.startswith(".") or f.endswith(".uploading"):
                    continue
                full = os.path.join(dp, f)
                if os.path.islink(full):
                    continue
                arc = nfc(os.path.join(name, os.path.relpath(full, real)))
                zi = zipfile.ZipInfo.from_file(full, arc)
                zi.compress_type = zipfile.ZIP_STORED
                with open(full, "rb") as src, z.open(zi, "w", force_zip64=True) as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)


def _need_write(root):
    if not root.writable:
        raise DriveError("你只能看，不能修改這個資料夾", 403)


def mkdir(scope, vpath, name):
    root, real = resolve(scope, vpath)
    _need_write(root)
    target = os.path.join(real, clean_name(name))
    if os.path.exists(target):
        raise DriveError("已經有同名的項目")
    os.mkdir(target)
    return {"ok": True}


def delete(scope, vpath):
    root, real = resolve(scope, vpath)
    _need_write(root)
    if real == os.path.realpath(root.path):
        raise DriveError("不能刪除最上層資料夾")
    if os.path.isdir(real):
        rmtree(real)
    else:
        remove(real)
    invalidate(root.path)
    return {"ok": True}


def rename(scope, vpath, new_name):
    root, real = resolve(scope, vpath)
    _need_write(root)
    if real == os.path.realpath(root.path):
        raise DriveError("不能改最上層資料夾的名字")
    target = os.path.join(os.path.dirname(real), clean_name(new_name))
    if os.path.exists(target):
        raise DriveError("已經有同名的項目")
    os.rename(real, target)
    return {"ok": True}


def upload(scope, vpath, name, length, rfile):
    """Stream the request body into vpath/name, enforcing the root's quota and the disk's free space."""
    root, real = resolve(scope, vpath)
    _need_write(root)
    if not os.path.isdir(real):
        raise DriveError("這不是資料夾")
    if root.quota and dir_size(root.path, ttl=5, wait=True) + length > root.quota:
        raise DriveError("超過你的容量上限", 413)
    if length > shutil.disk_usage(DRIVE_ROOT).free - (1 << 30):
        raise DriveError("硬碟空間不足", 507)
    name = clean_name(name)
    base, ext = os.path.splitext(name)
    target, n = os.path.join(real, name), 1
    while os.path.exists(target):
        target = os.path.join(real, f"{base} ({n}){ext}")
        n += 1
    part = target + ".uploading"
    done = 0
    try:
        with open(part, "wb") as f:
            while done < length:
                chunk = rfile.read(min(1 << 20, length - done))
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
        if done != length:
            raise DriveError("上傳中斷")
        os.rename(part, target)
    finally:
        if os.path.exists(part):
            remove(part)
    invalidate(root.path)
    return {"ok": True, "name": os.path.basename(target)}


def send_file(handler, scope, vpath, inline=False):
    """Serve a file with HTTP Range support so videos can be scrubbed in the browser."""
    _, real = resolve(scope, vpath)
    if not os.path.isfile(real):
        raise DriveError("這不是檔案")
    size = os.path.getsize(real)
    name = os.path.basename(real)
    mt = mimetypes.guess_type(name)[0] or "application/octet-stream"
    start, end, status = 0, size - 1, 200
    m = re.match(r"bytes=(\d*)-(\d*)$", handler.headers.get("Range", ""))
    if m and size:
        if m.group(1):
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else size - 1
        else:
            start = max(0, size - int(m.group(2)))
        end = min(end, size - 1)
        if start > end:
            handler.send_response(416)
            handler.send_header("Content-Range", f"bytes */{size}")
            handler.end_headers()
            return
        status = 206
    handler.send_response(status)
    show = inline and mt in PREVIEW
    handler.send_header("Content-Type", mt if show else "application/octet-stream")
    if mt != "application/pdf":
        handler.send_header("Content-Security-Policy", "sandbox")  # uploaded files never run script in our origin
    handler.send_header("Content-Length", str(end - start + 1))
    handler.send_header("Accept-Ranges", "bytes")
    if status == 206:
        handler.send_header("Content-Range", f"bytes {start}-{end}/{size}")
    disp = "inline" if show else "attachment"
    handler.send_header("Content-Disposition", f"{disp}; filename*=UTF-8''" + urllib.parse.quote(name))
    handler.end_headers()
    with open(real, "rb") as f:
        f.seek(start)
        left = end - start + 1
        while left > 0:
            chunk = f.read(min(1 << 20, left))
            if not chunk:
                break
            handler.wfile.write(chunk)
            left -= len(chunk)


# ---------- trash (30-day recycle bin inside each root) ----------
import hashlib
import json as _json
import subprocess
import tempfile
import uuid as _uuid

TRASH = ".trash"
TRASH_DAYS = 30


def _root_key_of(scope, root):
    return next(k for k, r in scope.items() if r is root)


def trash_item(scope, vpath):
    """Move a file/folder into <root>/.trash/<id>/ instead of deleting it."""
    root, real = resolve(scope, vpath)
    _need_write(root)
    if real == os.path.realpath(root.path):
        raise DriveError("不能刪除最上層資料夾")
    tid = time.strftime("%Y%m%d%H%M%S") + "-" + _uuid.uuid4().hex[:8]
    box = os.path.join(root.path, TRASH, tid)
    os.makedirs(box)
    rel = os.path.relpath(real, os.path.realpath(root.path))
    size = dir_size(real, wait=True) if os.path.isdir(real) else os.path.getsize(real)
    with open(os.path.join(box, ".meta.json"), "w") as f:
        _json.dump({"rel": rel, "name": os.path.basename(real), "dir": os.path.isdir(real), "size": size, "at": time.time()}, f, ensure_ascii=False)
    os.rename(real, os.path.join(box, os.path.basename(real)))
    invalidate(root.path)
    return {"ok": True}


def trash_list(scope):
    out = []
    for key, root in scope.items():
        tdir = os.path.join(root.path, TRASH)
        if not os.path.isdir(tdir):
            continue
        for tid in os.listdir(tdir):
            try:
                with open(os.path.join(tdir, tid, ".meta.json")) as f:
                    m = _json.load(f)
            except (OSError, ValueError):
                continue
            out.append({"id": f"{key}:{tid}", "name": nfc(m["name"]), "from": f"/{key}/{m['rel']}", "root": root.label,
                        "dir": m["dir"], "size": m["size"], "at": m["at"], "kind": kind(m["name"], m["dir"]),
                        "left_days": max(0, TRASH_DAYS - int((time.time() - m["at"]) // 86400)), "writable": root.writable})
    out.sort(key=lambda x: -x["at"])
    return {"ok": True, "items": out, "days": TRASH_DAYS}


def _trash_entry(scope, tid):
    key, _, name = str(tid).partition(":")
    if key not in scope or not re.match(r"^\d{14}-[0-9a-f]{8}$", name):
        raise DriveError("找不到這個項目", 404)
    root = scope[key]
    _need_write(root)
    box = os.path.join(root.path, TRASH, name)
    try:
        with open(os.path.join(box, ".meta.json")) as f:
            return root, box, _json.load(f)
    except (OSError, ValueError):
        raise DriveError("找不到這個項目", 404)


def trash_restore(scope, tid):
    root, box, m = _trash_entry(scope, tid)
    dest_dir = os.path.join(root.path, os.path.dirname(m["rel"]))
    os.makedirs(dest_dir, exist_ok=True)
    base, ext = os.path.splitext(m["name"])
    dest, n = os.path.join(dest_dir, m["name"]), 1
    while os.path.exists(dest):
        dest = os.path.join(dest_dir, f"{base} (還原{'' if n == 1 else ' ' + str(n)}){ext}")
        n += 1
    os.rename(os.path.join(box, m["name"]), dest)
    rmtree(box, ignore_errors=True)
    invalidate(root.path)
    return {"ok": True, "restored_to": "/" + os.path.relpath(dest, root.path)}


def trash_purge(scope, tid):
    _, box, _ = _trash_entry(scope, tid)
    rmtree(box)
    return {"ok": True}


def trash_empty(scope):
    n = 0
    for root in scope.values():
        if root.writable and os.path.isdir(os.path.join(root.path, TRASH)):
            for tid in os.listdir(os.path.join(root.path, TRASH)):
                rmtree(os.path.join(root.path, TRASH, tid), ignore_errors=True)
                n += 1
    return {"ok": True, "removed": n}


def purge_old_trash(paths):
    """Scheduler: drop trash older than TRASH_DAYS in every given root folder."""
    removed = 0
    for p in paths:
        tdir = os.path.join(p, TRASH)
        if not os.path.isdir(tdir):
            continue
        for tid in os.listdir(tdir):
            try:
                with open(os.path.join(tdir, tid, ".meta.json")) as f:
                    at = _json.load(f)["at"]
            except (OSError, ValueError, KeyError):
                at = os.path.getmtime(os.path.join(tdir, tid))
            if time.time() - at > TRASH_DAYS * 86400:
                rmtree(os.path.join(tdir, tid), ignore_errors=True)
                removed += 1
    return removed


# ---------- thumbnails ----------
THUMB_DIR = os.path.expanduser("~/homeserver/thumbs")
_thumb_sem = threading.Semaphore(2)


def thumb(scope, vpath, size=360):
    """Small JPEG preview for photos (sips, HEIC included) and videos (Quick Look); cached by path+mtime."""
    _, real = resolve(scope, vpath)
    k = kind(os.path.basename(real), False)
    if k not in ("image", "video", "pdf", "doc"):
        raise DriveError("沒有縮圖", 404)
    size = 1600 if int(size) > 360 else 360
    st = os.stat(real)
    key = hashlib.sha1(f"{real}|{st.st_mtime}|{st.st_size}|{size}".encode()).hexdigest()
    os.makedirs(THUMB_DIR, mode=0o700, exist_ok=True)
    out = os.path.join(THUMB_DIR, key + ".jpg")
    if os.path.exists(out):
        return out
    with _thumb_sem:
        if k == "image":
            subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "80" if size > 360 else "70", "-Z", str(size), real,
                            "--out", out], capture_output=True, timeout=30)
        else:
            with tempfile.TemporaryDirectory() as td:
                subprocess.run(["qlmanage", "-t", "-s", str(size), "-o", td, real], capture_output=True, timeout=40)
                pngs = [f for f in os.listdir(td) if f.endswith(".png")]
                if pngs:
                    subprocess.run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "80", os.path.join(td, pngs[0]),
                                    "--out", out], capture_output=True, timeout=30)
    if not os.path.exists(out):
        raise DriveError("無法產生縮圖", 404)
    return out


# ---------- search ----------
def search(scope, q, limit=200):
    q = nfc(str(q or "")).strip().lower()
    if len(q) < 1:
        return {"ok": True, "items": []}
    out = []
    bases = {os.path.realpath(r.path) for r in scope.values()}
    for key, root in scope.items():
        base = os.path.realpath(root.path)
        if not os.path.isdir(base):
            continue
        for dp, dns, fns in os.walk(base):
            # a root nested inside another one (the owner's own folder inside 成員資料夾) is searched only once, under its own name
            dns[:] = [d for d in dns if not d.startswith(".") and d not in HIDDEN and os.path.join(dp, d) not in bases]
            for name in dns + fns:
                if name.startswith(".") or q not in nfc(name).lower():
                    continue
                full = os.path.join(dp, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                is_dir = os.path.isdir(full)
                rel = os.path.relpath(full, base)
                out.append({"name": nfc(name), "path": nfc(f"/{key}/{rel}"), "folder": nfc(f"{root.label}/" + os.path.dirname(rel)),
                            "dir": is_dir, "size": 0 if is_dir else st.st_size, "mtime": st.st_mtime, "ctime": _born(st),
                            "kind": kind(name, is_dir)})
                if len(out) >= limit:
                    return {"ok": True, "items": out, "more": True}
    return {"ok": True, "items": out}
