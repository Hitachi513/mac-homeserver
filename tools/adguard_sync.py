#!/usr/bin/env python3
"""補上缺少的推薦 AdGuard 名單（只新增、不改動既有設定）。

推薦內容的來源是 launchd/AdGuardHome.yaml.in（新安裝用的模板）。這個工具不會直接改
AdGuardHome.yaml，而是沿用 dashboard.server 既有的本機 API 認證（credentials.txt）、
逾時與錯誤處理，只呼叫 AdGuard 的 API：

  * filter 以 URL 比對：缺少才用 filtering/add 新增（id 由 AdGuard 自己配）
  * user_rules 以整行比對：缺少才附加到最後，再用 filtering/set_rules 寫回

既有的 filter（包含被停用或改過名稱的）、既有 user_rules 的順序與內容都不動。
沒有缺少的項目時完全不寫入；失敗時盡量用 API 回滾，並保留時間戳備份。
"""
import base64
import getpass
import json
import os
import shutil
import sys
import time
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "dashboard"))
import server  # noqa: E402  (agh() / agh_auth()：與控制台相同的認證與逾時)
import settings  # noqa: E402

TEMPLATE = os.path.join(os.path.dirname(HERE), "launchd", "AdGuardHome.yaml.in")
AGH_YAML = os.path.join(settings.BASE, "AdGuardHome", "AdGuardHome.yaml")

_auth_override = None


def _yaml_str(v):
    """反轉模板裡用到的簡單 YAML 字串（雙引號走 JSON 轉義，單引號只處理 ''）。"""
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        try:
            return json.loads(v)
        except ValueError:
            return v[1:-1]
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1].replace("''", "'")
    return v


def recommended():
    """從模板取出 (filters, user_rules)；id 與 enabled 刻意忽略，不拿來比對。"""
    filters, rules, section, cur = [], [], None, None
    with open(TEMPLATE, encoding="utf-8") as f:
        for line in f.read().splitlines():
            if line.startswith("filters:"):
                section, cur = "filters", None
                continue
            if line.startswith("user_rules:"):
                section, cur = "rules", None
                continue
            if section and line and not line.startswith(" "):
                section = None  # 下一個 top-level 區塊，結束
            if section == "filters":
                if line.startswith("  - "):
                    cur = {}
                    filters.append(cur)
                    rest = line[4:].strip()
                    if rest.startswith("url:"):
                        cur["url"] = _yaml_str(rest[4:])
                elif cur is not None and ":" in line:
                    k, v = line.strip().split(":", 1)
                    if k in ("url", "name"):
                        cur[k] = _yaml_str(v)
            elif section == "rules" and line.startswith("  - "):
                rules.append(_yaml_str(line[4:]))
    return [f for f in filters if f.get("url")], rules


def _ask_auth(why):
    """既有憑證不能用時，才在終端機問密碼；只留在記憶體，不寫任何檔案。"""
    if not sys.stdin.isatty():
        return None
    user = "admin"
    try:
        with open(server.CRED_FILE) as f:
            line = next(l for l in f if l.startswith("AdGuard"))
        user = line.split()[-3]
    except Exception:
        pass
    pw = getpass.getpass(f"{why}請輸入 AdGuard 管理員 {user} 的密碼（只留在記憶體）：")
    if not pw:
        return None
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def _call(path, method="GET", body=None, timeout=10):
    """呼叫本機 AdGuard API；401 時（且是終端機）才詢問目前的管理密碼並重試一次。"""
    global _auth_override
    for attempt in (0, 1):
        if _auth_override is not None:
            server.agh_auth = lambda: _auth_override
        try:
            return server.agh(path, method, body, timeout)
        except urllib.error.HTTPError as e:
            if e.code != 401 or attempt or not sys.stdin.isatty():
                raise
            auth = _ask_auth("credentials.txt 的 AdGuard 密碼已無法登入，")
            if not auth:
                raise
            _auth_override = auth


def _backup():
    if not os.path.exists(AGH_YAML):
        return None
    dst = time.strftime(AGH_YAML + ".bak.%Y%m%d-%H%M%S")
    if os.path.exists(dst):
        dst += f".{os.getpid()}"
    shutil.copy2(AGH_YAML, dst)
    os.chmod(dst, 0o600)
    return dst


def _restore_file(path):
    try:
        shutil.copy2(path, AGH_YAML)
        os.chmod(AGH_YAML, 0o600)
        return True
    except OSError as e:
        print(f"還原失敗：{e}，備份仍在 {path}")
        return False


def _rollback(added_urls, original_rules, backup):
    """把剛剛新增的 filter／規則移除；任何一步失敗就退回備份檔並要使用者重啟 AdGuard。"""
    ok = True
    try:
        status = _call("filtering/status", timeout=10)
        for f in status.get("filters") or []:
            if str(f.get("url") or "").strip() in added_urls:
                _call("filtering/remove", "POST", {"id": f["id"], "name": f.get("name"),
                                                   "url": f.get("url"), "enabled": f.get("enabled")})
    except Exception as e:
        print(f"回滾過濾清單失敗：{e}")
        ok = False
    if original_rules is not None:
        try:
            _call("filtering/set_rules", "POST", {"rules": original_rules})
        except Exception as e:
            print(f"回滾自訂規則失敗：{e}")
            ok = False
    if not ok and backup:
        print("改用備份檔還原 AdGuardHome.yaml。")
        _restore_file(backup)
    return ok


def main():
    dry = "--dry-run" in sys.argv[1:]
    want_filters, want_rules = recommended()
    if not want_filters or not want_rules:
        print(f"讀不到推薦名單：{TEMPLATE}")
        return 1
    try:
        status = _call("filtering/status", timeout=10)
    except Exception as e:
        print(f"連不到本機 AdGuard API（{server.AGH_URL}）：{e}")
        print("請先確認 AdGuard Home 正在執行，或稍後再試。")
        return 2

    current = status.get("filters") or []
    existing_urls = {str(f.get("url") or "").strip() for f in current}
    missing_filters = [f for f in want_filters if f["url"].strip() not in existing_urls]
    rules = list(status.get("user_rules") or [])  # 原封不動，只在後面附加缺少的行
    missing_rules = [r for r in want_rules if r not in rules]

    print(f"目前過濾清單 {len(current)} 條、自訂規則 {len(rules)} 行。")
    if not missing_filters and not missing_rules:
        print("推薦名單都已經在了，沒有改動任何設定。")
        return 0
    for f in missing_filters:
        print(f"  缺少過濾清單：{f.get('name') or f['url']}")
    for r in missing_rules:
        print(f"  缺少自訂規則：{r}")
    if dry:
        print("（--dry-run：沒有寫入任何設定）")
        return 0

    backup = _backup()
    print(f"已備份 AdGuardHome.yaml：{backup}" if backup else "找不到 AdGuardHome.yaml，略過檔案備份。")
    added_urls = set()
    rules_attempted = False
    original_rules = rules if missing_rules else None
    try:
        for f in missing_filters:
            _call("filtering/add", "POST", {"name": f.get("name") or f["url"], "url": f["url"], "enabled": True})
            added_urls.add(f["url"].strip())
        if missing_rules:
            rules_attempted = True
            _call("filtering/set_rules", "POST", {"rules": rules + missing_rules})
    except Exception as e:
        print(f"套用失敗：{e}")
        _rollback(added_urls, original_rules if rules_attempted else None, backup)
        return 1

    print(f"完成：新增 {len(missing_filters)} 條過濾清單、{len(missing_rules)} 行自訂規則；既有設定未變動。")
    if missing_filters:
        print("新清單的規則會在 AdGuard 下一次更新時下載，也可以在管理頁按「更新過濾清單」。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
