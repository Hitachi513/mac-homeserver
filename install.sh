#!/bin/bash
# 家用伺服器安裝程式（macOS）
#   git clone https://github.com/Hitachi513/mac-homeserver ~/homeserver
#   bash ~/homeserver/install.sh
# 可以重複執行：已經裝好的部分會跳過或更新。
set -euo pipefail

BASE="$HOME/homeserver"
HERE="$(cd "$(dirname "$0")" && pwd)"
say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { echo "  ✅ $*"; }
warn() { echo "  ⚠️  $*"; }
die()  { echo "  ❌ $*"; exit 1; }
ask()  { local q="$1" def="${2:-}" a; read -r -p "  $q${def:+ [$def]}: " a </dev/tty; echo "${a:-$def}"; }
yes()  { local a; a="$(ask "$1 (y/n)" "${2:-n}")"; [[ "$a" =~ ^[Yy] ]]; }
# Messages follow the Mac's language (dashboard/i18n.py): T '中文模板 {1}' value…
UI_LANG="$(defaults read -g AppleLanguages 2>/dev/null | sed -n 2p | tr -d ' ",')"
T() { local s="$1"; shift; /usr/bin/python3 "$BASE/dashboard/i18n.py" "${UI_LANG:-${LANG:-zh-TW}}" "$s" "$@" 2>/dev/null || echo "$s"; }

[ "$(uname)" = Darwin ] || die "$(T '只支援 macOS')"
[ "$HERE" = "$BASE" ] || die "$(T '請把專案放在 {1}（git clone … ~/homeserver），程式裡的路徑固定在這裡' "$BASE")"
[ "$(id -u)" != 0 ] || die "$(T '不要用 sudo 執行；需要管理員權限的步驟會另外提示')"

# ---------------------------------------------------------------- 1. requirements
say "1) $(T '檢查需要的軟體')"
TS="$(command -v tailscale || echo /Applications/Tailscale.app/Contents/MacOS/Tailscale)"
[ -x "$TS" ] || die "$(T '請先安裝 Tailscale（https://tailscale.com/download/mac）並登入，再執行一次')"
STATUS="$("$TS" status --json 2>/dev/null)" || die "$(T 'Tailscale 沒有在執行，請打開 Tailscale 並登入')"
TS_HOST="$(/usr/bin/python3 -c 'import json,sys; print(json.loads(sys.argv[1])["Self"]["DNSName"].rstrip("."))' "$STATUS")"
TS_LOGIN="$(/usr/bin/python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["User"][str(d["Self"]["UserID"])]["LoginName"])' "$STATUS")"
[ -n "$TS_HOST" ] || die "$(T '讀不到這台 Mac 的 Tailscale 名稱（請在 Tailscale 後台打開 MagicDNS 和 HTTPS 憑證）')"
ok "Tailscale：$TS_HOST（$TS_LOGIN）"
/usr/bin/python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null || die "$(T '需要 Python 3.9 以上（執行 xcode-select --install）')"
ok "Python：$(/usr/bin/python3 --version)"
BREW="$(command -v brew || true)"
[ -n "$BREW" ] && ok "$(T 'Homebrew：已安裝')" || warn "$(T '沒有 Homebrew（只有 Shadowrocket 功能需要，https://brew.sh）')"

# ---------------------------------------------------------------- 2. config
say "2) $(T '設定')"
CFG="$BASE/config.json"
if [ -f "$CFG" ]; then
  ok "$(T '已經有 config.json，沿用（要改請直接編輯 {1}）' "$CFG")"
else
  OWNER="$(ask "$(T '控制台擁有者的 Tailscale 帳號')" "$TS_LOGIN")"
  echo "  $(T '目前接上的磁碟：')"; ls /Volumes | sed 's/^/    - /'
  DISK="$(ask "$(T '要當雲端硬碟的外接磁碟名稱（上面清單其中一個）')" "$(ls /Volumes | grep -v '^Macintosh HD$' | head -1)")"
  [ -d "/Volumes/$DISK" ] || warn "$(T '{1} 現在沒有接上，之後接上就會自動使用' "/Volumes/$DISK")"
  SR=false
  echo
  echo "  $(T 'Shadowrocket 功能讓成員不裝 Tailscale、用 Shadowrocket 走你家的網路。')"
  echo "  $(T '在部分國家或地區，架設這類代理服務可能違法，請先確認當地法律，責任由你自行負擔。')"
  yes "$(T '要開啟 Shadowrocket 功能嗎')" n && SR=true
  /usr/bin/python3 - "$CFG" "$OWNER" "$DISK" "$SR" <<'PY'
import json, sys
path, owner, disk, sr = sys.argv[1:]
cfg = {"owners": [owner], "drive_root": f"/Volumes/{disk}/HomeCloud", "drive_name": disk,
       "label_prefix": "local.homeserver", "shadowrocket": sr == "true", "contact": "https://github.com"}
with open(path, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PY
  chmod 600 "$CFG"
  ok "$(T '已寫入 {1}' "$CFG")"
fi
read_cfg() { /usr/bin/python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(str(v).lower() if isinstance(v,bool) else v)' "$CFG" "$1"; }
PREFIX="$(read_cfg label_prefix)"; SR="$(read_cfg shadowrocket)"
chmod 700 "$BASE"

# ---------------------------------------------------------------- 3. python packages
say "3) $(T 'Python 套件')"
/usr/bin/python3 -m pip install --user --quiet --disable-pip-version-check -r "$BASE/requirements.txt"
ok "cryptography、cbor2"
# launchd must start the real Python.app binary, otherwise the Full Disk Access you grant it won't apply
PY="$(/usr/bin/python3 -c 'import sys,os; p=os.path.realpath(sys.executable); a=p.split("/bin/")[0]+"/Resources/Python.app/Contents/MacOS/Python"; print(a if os.path.exists(a) else p)')"

# ---------------------------------------------------------------- 4. AdGuard Home
say "4) $(T '擋廣告（AdGuard Home）')"
AGH="$BASE/AdGuardHome"
if [ ! -x "$AGH/AdGuardHome" ]; then
  ARCH="$( [ "$(uname -m)" = arm64 ] && echo arm64 || echo amd64 )"
  TMP="$(mktemp -d)"
  curl -fsSL -o "$TMP/agh.zip" "https://github.com/AdguardTeam/AdGuardHome/releases/latest/download/AdGuardHome_darwin_${ARCH}.zip"
  unzip -q "$TMP/agh.zip" -d "$TMP" && mkdir -p "$AGH" && cp "$TMP/AdGuardHome/AdGuardHome" "$AGH/" && rm -rf "$TMP"
  ok "$(T '已下載 AdGuard Home')"
fi
if [ ! -f "$AGH/AdGuardHome.yaml" ]; then
  # Write a finished config instead of using the first-run wizard (which insists on running as root on macOS):
  # web UI on localhost only, DNS answers only this Mac and the tailnet, DNS-over-HTTPS upstreams, random password.
  AGH_PW="$(/usr/bin/python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  AGH_HASH="$(htpasswd -bnBC 10 "" "$AGH_PW" | tr -d ':\n' | sed 's/^\$2y/\$2a/')"
  sed -e "s#@AGH_HASH@#$AGH_HASH#" -e "s#@AGH_WEB_PORT@#3000#" -e "s#@AGH_DNS_PORT@#53#" -e "s#@BASE@#$BASE#g" \
    "$BASE/launchd/AdGuardHome.yaml.in" > "$AGH/AdGuardHome.yaml"
  umask 077; echo "AdGuard Home  admin / $AGH_PW" > "$BASE/credentials.txt"; umask 022
  ok "$(T 'AdGuard 已設定（只服務本機和 Tailscale），管理密碼存在 {1}（只有你讀得到）' "$BASE/credentials.txt")"
fi
chmod 600 "$AGH/AdGuardHome.yaml" "$BASE/credentials.txt" 2>/dev/null || true

# ---------------------------------------------------------------- 5. Shadowrocket (optional)
XRAY=""
if [ "$SR" = true ]; then
  say "5) Shadowrocket（Xray）"
  [ -n "$BREW" ] || die "$(T 'Shadowrocket 功能需要 Homebrew：先安裝 https://brew.sh 再執行一次')"
  command -v xray >/dev/null || "$BREW" install xray
  XRAY="$(command -v xray)"; mkdir -p "$BASE/xray"; chmod 700 "$BASE/xray"
  ok "Xray：$("$XRAY" version | head -1 | cut -d' ' -f1-2)"
else
  say "5) $(T 'Shadowrocket：沒有開啟（略過）')"
fi

# ---------------------------------------------------------------- 6. web remote desktop (optional)
VNC=false
say "6) $(T '網頁遠端桌面（noVNC，選用）')"
if [ -d "$BASE/noVNC" ] || yes "$(T '要開啟「在手機網頁上遠端操作 Mac」嗎（需要打開 Mac 的螢幕共享）')" n; then
  VNC=true
  if [ ! -d "$BASE/noVNC" ]; then
    TMP="$(mktemp -d)"
    curl -fsSL -o "$TMP/novnc.tgz" https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.tar.gz
    tar -xzf "$TMP/novnc.tgz" -C "$TMP" && mv "$TMP/noVNC-1.5.0" "$BASE/noVNC" && rm -rf "$TMP"
  fi
  [ -x "$BASE/venv/bin/websockify" ] || { /usr/bin/python3 -m venv "$BASE/venv" && "$BASE/venv/bin/pip" install --quiet websockify; }
  ok "$(T 'noVNC 已安裝（記得到 系統設定 → 一般 → 共享 → 打開「螢幕共享」）')"
fi

# ---------------------------------------------------------------- 7. background services
say "7) $(T '背景服務（開機自動啟動）')"
LA="$HOME/Library/LaunchAgents"; mkdir -p "$LA"
install_agent() {   # name
  local src="$BASE/launchd/$1.plist.in" dst="$LA/$PREFIX.$1.plist"
  sed -e "s#@PREFIX@#$PREFIX#g" -e "s#@BASE@#$BASE#g" -e "s#@PYTHON@#$PY#g" -e "s#@XRAY@#$XRAY#g" -e "s#@HOST@#$TS_HOST#g" "$src" > "$dst"
  launchctl bootout "gui/$(id -u)/$PREFIX.$1" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$dst"
  ok "$PREFIX.$1"
}
install_agent adguardhome
[ "$SR" = true ] && install_agent xray
[ "$VNC" = true ] && install_agent novnc
install_agent homepanel

# ---------------------------------------------------------------- 8. Tailscale serve / funnel
say "8) $(T '用 Tailscale 發布（控制台只有你的 Tailscale 連得到）')"
"$TS" serve --bg --https=443 http://127.0.0.1:8088 >/dev/null && ok "$(T '控制台：{1}' "https://$TS_HOST")"
"$TS" serve --bg --https=3443 http://127.0.0.1:3000 >/dev/null && ok "$(T 'AdGuard 管理頁：{1}' "https://$TS_HOST:3443")"
[ "$VNC" = true ] && "$TS" serve --bg --https=6443 http://127.0.0.1:6080 >/dev/null && ok "$(T '遠端桌面：{1}' "https://$TS_HOST:6443/vnc.html")"
if "$TS" funnel --bg --https=8443 --set-path=/p http://127.0.0.1:8090 >/dev/null 2>&1; then
  ok "$(T '成員網頁（公開，用秘密網址保護）：{1}' "https://$TS_HOST:8443/p/…")"
  [ "$SR" = true ] && "$TS" funnel --bg --https=8443 http://127.0.0.1:10080 >/dev/null && ok "$(T 'Shadowrocket 入口：{1}' "https://$TS_HOST:8443")"
else
  warn "$(T 'Funnel 還沒開放：到 https://login.tailscale.com/admin/acls 加入 funnel 權限後再執行一次（成員網頁需要它）')"
fi

# ---------------------------------------------------------------- done
say "$(T '完成！接下來：')"
echo "  1. $(T '用 iPhone 打開 Tailscale，再用 Safari 開 {1}' "https://$TS_HOST")"
echo "     $(T '第一次會請你設定 4 位數密碼，可以再加 Face ID。')"
echo "  2. $(T '系統設定 → 隱私權與安全性 → 完整取用磁碟 → 加入：')"
echo "       $PY"
echo "     $(T '（雲端硬碟要讀外接硬碟需要這個權限）')"
echo "  3. $(T '控制台 → 設定 → 安全 → 「踢裝置設定」：設定踢人密碼、連結 Tailscale API，成員權限才能自動套用。')"
echo "  4. $(T '加強防火牆（建議，需要輸入 Mac 密碼）：')"
echo "       sudo bash $BASE/security/harden.sh"
echo "  5. $(T '讓開著 Tailscale 的裝置都擋廣告：Tailscale 後台 → DNS → Global nameservers → Add nameserver → Custom，填 {1}，再打開「Override DNS servers」。' "$("$TS" ip -4 2>/dev/null | head -1)")"
echo "     $(T '這台 Mac 自己要直接用 AdGuard（Tailscale 的 DNS 沒辦法轉給自己，不改會查不到網址）：')"
echo "       networksetup -setdnsservers Wi-Fi 127.0.0.1 ::1 && \"$TS\" set --accept-dns=false"
echo "  6. $(T '控制台 → 設定 → 安全，看安全分數並按「自我攻擊測試」。')"
