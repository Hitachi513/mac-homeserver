"""Languages. The UI is written in Traditional Chinese; i18n/strings.json maps each source string (with {1} {2}…
for interpolated parts) to its translations. Pages get the dictionary for their language through
i18n-<lang>-<version>.js (static/i18n.js does the rest in the browser); push notifications, the Windows agent
and the installer use t() here. Refresh the string list with tools/i18n_extract.py."""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STRINGS = os.path.join(HERE, "i18n", "strings.json")
RUNTIME = os.path.join(HERE, "static", "i18n.js")
LANGS = ["zh-TW", "en", "zh-CN", "ja", "ko", "es"]
DEFAULT = "en"  # for a browser language we don't have
HAN = re.compile(r"[㐀-鿿]")

_cache = {"mtime": None, "data": {}, "tables": {}, "patterns": {}, "js": {}, "ver": ""}


def _load():
    try:
        m = (os.path.getmtime(STRINGS), os.path.getmtime(RUNTIME))
    except OSError:
        m = None
    if m == _cache["mtime"]:
        return
    try:
        with open(STRINGS, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    h = hashlib.sha1()
    for p in (STRINGS, RUNTIME):
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except OSError:
            pass
    _cache.update(mtime=m, data=data, tables={}, patterns={}, js={}, ver=h.hexdigest()[:10])


def normalize(lang):
    lang = (lang or "").strip()
    if lang in LANGS:
        return lang
    low = lang.lower()
    if re.match(r"zh[-_](tw|hk|mo|hant)", low):
        return "zh-TW"
    if low.startswith("zh"):
        return "zh-CN"
    for l in ("en", "ja", "ko", "es"):
        if low.startswith(l):
            return l
    return None


def pick(cookie_lang=None, accept=None):
    """The language a page should use: an explicit choice (cookie), else the browser's list."""
    if normalize(cookie_lang):
        return normalize(cookie_lang)
    for part in (accept or "").split(","):
        lang = normalize(part.split(";")[0])
        if lang:
            return lang
    return DEFAULT if accept else "zh-TW"


def version():
    _load()
    return _cache["ver"]


def table(lang):
    _load()
    if lang not in _cache["tables"]:
        _cache["tables"][lang] = {k: v[lang] for k, v in _cache["data"].items() if lang != "zh-TW" and (v.get(lang) or "")}
    return _cache["tables"][lang]


def script(lang):
    """The page script for one language: its dictionary followed by the runtime."""
    lang = lang if lang in LANGS else DEFAULT
    _load()
    if lang not in _cache["js"]:
        with open(RUNTIME, encoding="utf-8") as f:
            runtime = f.read()
        head = "window.I18N_LANG=%s;window.I18N_DICT=%s;\n" % (json.dumps(lang), json.dumps(table(lang), ensure_ascii=False, separators=(",", ":")))
        _cache["js"][lang] = (head + runtime).encode()
    return _cache["js"][lang]


def script_name(lang):
    return f"i18n-{lang}-{version()}.js"


def parse_script_name(name):
    """'i18n-en-abc123.js' -> 'en' (any version is served; the URL only changes to bust caches)."""
    m = re.match(r"^i18n-([A-Za-z-]+)-[0-9a-f]+\.js$", name or "")
    return m.group(1) if m and m.group(1) in LANGS else None


def _patterns(lang):
    if lang not in _cache["patterns"]:
        out = []
        for k, v in table(lang).items():
            if "{1}" not in k:
                continue
            order, parts = [], re.split(r"\{(\d+)\}", k)
            for i in range(1, len(parts), 2):  # same rules as compile() in static/i18n.js
                order.append(parts[i])
                if i == 1 and parts[0] == "" and parts[i + 1].startswith(" "):
                    parts[i + 1], parts[i] = parts[i + 1][1:], r"(?:([\s\S]*?)\s+)?"
                elif i == len(parts) - 2 and parts[i + 1] == "" and parts[i - 1].endswith(" "):
                    parts[i - 1], parts[i] = parts[i - 1][:-1], r"(?:\s+([\s\S]*?))?"
                else:
                    parts[i] = r"([\s\S]*?)"
            rx = "".join(p if i % 2 else re.escape(p).replace(r"\ ", r"\s*").replace(" ", r"\s*") for i, p in enumerate(parts))
            out.append((len(re.sub(r"\{\d+\}", "", k)), re.compile("^" + rx + "$"), order, v))
        out.sort(key=lambda x: -x[0])
        _cache["patterns"][lang] = out
    return _cache["patterns"][lang]


def _via_patterns(body, lang, strict):
    for _, rx, order, to in _patterns(lang):
        m = rx.match(body)
        if not m:
            continue
        slots, ok = {}, True
        for n, v in zip(order, m.groups()):
            v = v or ""
            tv = v.strip()
            tr = _core(tv, lang) if HAN.search(tv) else tv
            if strict and HAN.search(tv) and tr == tv:
                ok = False
                break
            slots[n] = v.replace(tv, tr) if tv else v
        if ok:
            return re.sub(r"\{(\d+)\}", lambda x: slots.get(x.group(1), x.group(0)), to)
    return None


def _core(body, lang, depth=0):
    """Same steps as the browser: exact, safe template, split at ・, leading symbols, loose template."""
    if not HAN.search(body) or depth > 4:
        return body
    tab = table(lang)
    if body in tab:
        return tab[body]
    out = _via_patterns(body, lang, True)
    if out is None and "・" in body:
        parts = [p.strip() for p in body.split("・")]
        tr = [_core(p, lang, depth + 1) if _core(p, lang, depth + 1) != p else re.sub(r"^\s*[・·]\s*", "", tab.get("・" + p, p)) for p in parts]
        if tr != parts:
            out = ("・" if lang.startswith(("zh", "ja")) else " · ").join(x for x in tr if x)
    if out is None and "、" in body:
        parts = [p.strip() for p in body.split("、")]
        tr = [_core(p, lang, depth + 1) for p in parts]
        if tr != parts:
            out = ("、" if lang.startswith(("zh", "ja")) else ", ").join(tr)
    if out is None:
        m = re.match(r"^([●○•#\d\s%.,:+\-]+)(.*[\u3400-\u9fff].*)$", body, re.S)
        if m and _core(m.group(2), lang, depth + 1) != m.group(2):
            out = m.group(1) + _core(m.group(2), lang, depth + 1)
    if out is None:
        out = _via_patterns(body, lang, False)
    return out if out else body


def t(text, lang):
    """Translate one finished string (same matching as the browser)."""
    if not text or lang == "zh-TW" or not HAN.search(str(text)):
        return text
    _load()
    text = str(text)
    body = re.sub(r"\s+", " ", text.strip())
    out = _core(body, lang)
    return text if out == body else text.replace(text.strip(), out) if text.strip() == body else out


if __name__ == "__main__":
    # for the shell scripts: python3 i18n.py <lang> <template> [values for {1} {2}…]
    if len(sys.argv) > 2:
        out = t(sys.argv[2], normalize(sys.argv[1]) or "zh-TW")
        args = sys.argv[3:]
        print(re.sub(r"\{(\d+)\}", lambda m: args[int(m.group(1)) - 1] if int(m.group(1)) <= len(args) else m.group(0), out))
