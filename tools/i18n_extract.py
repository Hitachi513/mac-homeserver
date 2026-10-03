#!/usr/bin/env python3
"""Collect every user-visible Traditional Chinese string into dashboard/i18n/strings.json.

The UI is written in Traditional Chinese; translations are keyed by that source text. Strings with
interpolation become templates with numbered slots, e.g. `已擋 ${n} 筆` -> "已擋 {1} 筆". Markup is split at
tags, the same way the browser splits it into text nodes, so each key matches what the runtime sees.

    python3 tools/i18n_extract.py          # add new strings (existing translations are kept)
    python3 tools/i18n_extract.py --check  # list strings that still miss a translation
"""
import ast
import html
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "dashboard", "i18n", "strings.json")
LANGS = ["en", "zh-CN", "ja", "ko", "es"]
CJK = re.compile(r"[㐀-鿿]")
SLOT = "\x00"

WEB = ["dashboard/index.html", "dashboard/portal.html", "dashboard/share.html", "dashboard/static/drive.js"]
PY = ["dashboard/server.py", "dashboard/notify.py", "dashboard/bugs.py", "dashboard/portalauth.py", "dashboard/drive.py",
      "dashboard/security.py", "dashboard/applock.py", "dashboard/winagent.py", "dashboard/settings.py"]
SCRIPTS = ["dashboard/winagent/agent.ps1", "dashboard/winagent/install.ps1"]
SHELL = ["install.sh", "uninstall.sh", "security/harden.sh", "security/undo.sh"]


# Sentences the code builds with "+" (a number or name glued to Chinese), which a literal scan can't see.
EXTRA = [
    "{1} 天", "{1} 天前", "{1} 小時", "{1} 小時前", "{1} 分", "{1} 分鐘", "{1} 分鐘前", "{1} 台", "{1} 項", "{1} 個", "{1}/秒", "{1} B/秒",
    "{1}%（建議更換）", "{1}時{2}分", "{1}時", "{1} 小時 {2} 分", "已封鎖 {1}", "已放行 {1}", "已踢出 {1}", "已停止 port {1}", "控制台 {1} 項",
    "雲端 {1}", "今天 {1}", "昨天 {1}", "{1} 修改", "{1} 建立", "{1} 上傳", "搜尋「{1}」", "{1} 個資料夾", "{1} 個檔案", "共 {1}",
    "已還原到 {1}", "還要約 {1}", "還要約 {1} 分鐘", "還要約 {1} 秒", "嚴重度 {1}", "優先 {1}", "{1} 的回報", "{1} 的客戶端網址", "{1} 的 Shadowrocket",
    "{1}（你）", "已複製 {1} 的客戶端網址", "已重設 {1} 的控制台密碼", "直連 {1}", "中繼 {1}", "最後上線 {1}", "其他檔案 {1}",
    "開啟失敗：{1}", "截圖：{1}", "{1} 沒有在播放", "容量上限 {1}", "{1} 分鐘內有效", "私下回報・{1}", "GitHub：{1}", "{1}，", "已用 {1} 分",
    "每天 {1} 小時", "每天 {1} 分鐘", "移動 {1} 個項目 到…", "移動「{1}」 到…", "{1} 個項目", "已連線",
    "已啟用，{1} 條規則（{2} 分鐘前回報）", "已啟用，{1} 條規則（超過 30 分鐘沒有回報）", "規則沒有載入（{1} 分鐘前回報）",
    "規則沒有載入（超過 30 分鐘沒有回報）", "{1}：已由封包過濾限制為只有 Tailscale", "{1}：目前家裡網路也連得到",
    "{1} 核心（{2} 效能 + {3} 節能）", "{1} 記憶體", "Wi-Fi（{1}）",
    # short words for the bottom bar (navLabel in index.html)
    "選單：首頁", "選單：雲端", "選單：擋廣告", "選單：遙控", "選單：成員", "選單：設定",
]


def segments(text):
    """Split a literal (slots marked with SLOT) at HTML tags into normalised text-node templates."""
    out = []
    for m in re.finditer(r'\b(?:placeholder|title|aria-label|alt|data-confirm-text)="([^"]*)"', text):
        out += segments(m.group(1))
    for part in re.split(r"<[^<>]*>", text):
        part = html.unescape(part)
        part = re.sub(r"\s+", " ", part).strip()
        if not CJK.search(part):
            continue
        n = 0

        def num(_):
            nonlocal n
            n += 1
            return "{%d}" % n
        out.append(re.sub(SLOT, num, part))
    return out


# ---------- JavaScript (also inline <script> blocks) ----------
JS_ESC = {"n": "\n", "t": "\t", "r": "", "'": "'", '"': '"', "`": "`", "\\": "\\", "$": "$", "/": "/"}


def js_literals(src):
    """Yield string / template literal contents (with SLOT for ${...}), skipping comments and regexes."""
    i, n = 0, len(src)
    prev = ""  # last significant char, to tell a regex from a division
    while i < n:
        c = src[i]
        if c == "/" and src[i + 1:i + 2] == "/":
            i = src.find("\n", i)
            i = n if i < 0 else i
            continue
        if c == "/" and src[i + 1:i + 2] == "*":
            i = src.find("*/", i + 2)
            i = n if i < 0 else i + 2
            continue
        if c == "/" and (prev == "" or prev in "(,=:[!&|?{};+-*%<>~^"):
            j = i + 1
            cls = False
            while j < n and (src[j] != "/" or cls):
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    cls = True
                elif src[j] == "]":
                    cls = False
                elif src[j] == "\n":
                    break
                j += 1
            i = j + 1
            prev = "/"
            continue
        if c in "'\"":
            j, buf = i + 1, []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(JS_ESC.get(src[j + 1], src[j + 1]))
                    j += 2
                    continue
                if src[j] == "\n":
                    break
                buf.append(src[j])
                j += 1
            yield "".join(buf)
            i = j + 1
            prev = "a"
            continue
        if c == "`":
            text, i = template(src, i + 1)
            yield text
            prev = "a"
            continue
        if not c.isspace():
            prev = c
        i += 1


def template(src, i):
    """Parse a template literal starting after the backtick. Nested literals inside ${} are yielded via
    the module-level list NESTED. Returns (text with SLOTs, index after the closing backtick)."""
    buf, n = [], len(src)
    while i < n and src[i] != "`":
        if src[i] == "\\" and i + 1 < n:
            buf.append(JS_ESC.get(src[i + 1], src[i + 1]))
            i += 2
            continue
        if src[i] == "$" and src[i + 1:i + 2] == "{":
            depth, j = 1, i + 2
            start = j
            while j < n and depth:
                ch = src[j]
                if ch in "'\"`":  # skip over nested literals while matching braces
                    if ch == "`":
                        _, j = template(src, j + 1)
                        continue
                    k = j + 1
                    while k < n and src[k] != ch:
                        k += 2 if src[k] == "\\" else 1
                    j = k + 1
                    continue
                depth += {"{": 1, "}": -1}.get(ch, 0)
                j += 1
            NESTED.append(src[start:j - 1])
            buf.append(SLOT)
            i = j
            continue
        buf.append(src[i])
        i += 1
    return "".join(buf), i + 1


NESTED = []


def scan_js(src):
    found = []
    queue = [src]
    while queue:
        code = queue.pop()
        for lit in js_literals(code):
            found += segments(lit)
        while NESTED:
            queue.append(NESTED.pop())
    return found


def scan_html(src):
    found = []
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", src, re.S):
        found += scan_js(m.group(1))
    markup = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<!--.*?-->", "", src, flags=re.S)
    for m in re.finditer(r'\b(?:placeholder|title|aria-label|alt|content|data-confirm-text)="([^"]*)"', markup):
        found += segments(m.group(1))
    markup = re.sub(r"<[^<>]*>", "<>", markup)  # attributes are handled above; keep only text between tags
    found += segments(markup)
    return found


# ---------- Python ----------
def scan_py(src):
    tree, found, docs = ast.parse(src), [], set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant):
                docs.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    parts.append(SLOT)
            for v in node.values:
                if isinstance(v, ast.Constant):
                    docs.add(id(v))  # its pieces are covered by the whole template
            found += [s for s in segments("".join(parts))]
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            found += segments(node.value)
    return found


def scan_ps(src):
    src = re.sub(r"(?m)^\s*#.*$", "", src)
    found = []
    for m in re.finditer(r"'((?:[^'\n]|'')*)'|\"((?:[^\"\n`]|`.)*)\"", src):
        found += segments((m.group(1) or m.group(2) or "").replace("''", "'"))
    return found


def collect():
    keys = {}
    for f in WEB:
        src = open(os.path.join(ROOT, f), encoding="utf-8").read()
        for k in (scan_html(src) if f.endswith(".html") else scan_js(src)):
            keys.setdefault(k, set()).add(os.path.basename(f))
    for f in PY:
        for k in scan_py(open(os.path.join(ROOT, f), encoding="utf-8").read()):
            keys.setdefault(k, set()).add(os.path.basename(f))
    for f in SHELL:  # messages go through T '…' (see install.sh)
        for m in re.finditer(r"\bT\s+'([^']*)'|\bT\s+\"([^\"]*)\"", open(os.path.join(ROOT, f), encoding="utf-8").read()):
            for k in segments(m.group(1) or m.group(2)):
                keys.setdefault(k, set()).add(os.path.basename(f))
    for k in EXTRA:
        keys.setdefault(k, set()).add("built in code")
    for f in SCRIPTS:
        for k in scan_ps(open(os.path.join(ROOT, f), encoding="utf-8").read()):
            keys.setdefault(k, set()).add(os.path.basename(f))
    return keys


def main():
    keys = collect()
    try:
        with open(OUT, encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, ValueError):
        old = {}
    if "--check" in sys.argv:
        missing = [k for k in keys if any(not (old.get(k) or {}).get(l) for l in LANGS)]
        print(f"{len(keys)} strings, {len(missing)} missing a translation")
        for k in missing:
            print("  " + k)
        sys.exit(1 if missing else 0)
    out = {k: {l: (old.get(k) or {}).get(l, "") for l in LANGS} for k in sorted(keys)}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    gone = [k for k in old if k not in keys]
    print(f"{len(out)} strings ({len(out) - len([k for k in out if k in old])} new, {len(gone)} no longer used and dropped)")


if __name__ == "__main__":
    main()
